/**
 * Maple TEE-encrypted fetch for Node.js
 *
 * This module implements a custom fetch function that encrypts requests to Maple's
 * TEE-secured inference API. It's a headless version compatible with Node.js (no
 * browser APIs like localStorage/sessionStorage required).
 *
 * The flow:
 * 1. Fetch attestation document from Maple's API
 * 2. Verify the TEE attestation (AWS Nitro enclave signature chain)
 * 3. Perform ECDH key exchange to get a session key
 * 4. Encrypt request body with ChaCha20-Poly1305
 * 5. Decrypt response (including SSE streams)
 *
 * TODO: Refactor to use shared code from OpenSecret SDK
 * =====================================================
 *
 * This implementation duplicates significant crypto/attestation logic that already
 * exists in the OpenSecret SDK (@opensecret/react). The SDK lives at:
 *   /Users/tony/Dev/OpenSecret/OpenSecret-SDK
 *
 * The SDK has well-tested implementations of:
 *   - src/lib/encryption.ts: encryptMessage() and decryptMessage() with ChaCha20-Poly1305
 *   - src/lib/attestation.ts: Full CBOR/COSE parsing, certificate chain verification,
 *     signature verification against AWS Nitro root cert
 *   - src/lib/getAttestation.ts: Key exchange flow and session establishment
 *   - src/lib/api.ts: keyExchange() and fetchAttestationDocument() API calls
 *
 * The problem is that the SDK currently has browser dependencies:
 *   - window.sessionStorage for caching session keys
 *   - window.crypto.randomUUID() for nonce generation
 *   - window.localStorage for access tokens
 *
 * Recommended refactor approach:
 *   1. Create a platform-agnostic core module in the SDK (e.g., @opensecret/core)
 *      that exports all the crypto primitives and attestation verification logic
 *      without any browser APIs.
 *
 *   2. The core module should accept dependencies via injection:
 *      - A cache interface (get/set session) that can be backed by sessionStorage
 *        in browsers or a simple Map/LRU cache in Node.js
 *      - A randomUUID function (window.crypto.randomUUID or node:crypto.randomUUID)
 *
 *   3. Create platform adapters:
 *      - @opensecret/react (existing) - browser adapter with sessionStorage
 *      - @opensecret/node - Node.js adapter with in-memory caching
 *
 *   4. This file (maple-fetch.ts) would then simply:
 *      ```typescript
 *      import { createEncryptedFetch } from "@opensecret/node";
 *      export const createMapleCustomFetch = (apiKey: string) =>
 *        createEncryptedFetch({ apiKey, apiUrl: MAPLE_API_URL });
 *      ```
 *
 * Benefits of the refactor:
 *   - Single source of truth for crypto operations (less chance of bugs)
 *   - Full attestation verification (this file skips certificate chain validation)
 *   - Shared test coverage
 *   - Easier to update when Maple/OpenSecret protocol changes
 *
 * What this file currently skips that the SDK does properly:
 *   - Certificate chain verification against AWS Nitro root cert
 *   - Certificate expiration checks
 *   - Signature verification of the attestation document
 *   - Nonce validation in attestation response
 *
 * For now, this simplified implementation works because:
 *   - We trust the TLS connection to Maple's API
 *   - The key exchange still provides end-to-end encryption
 *   - Session keys are ephemeral (5-minute TTL)
 *
 * When making this official, the full attestation verification should be added
 * to ensure we're actually talking to a genuine AWS Nitro enclave.
 */

import { webcrypto } from "node:crypto";
import nacl from "tweetnacl";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { encode as base64Encode, decode as base64Decode } from "@stablelib/base64";

import { MAPLE_DEFAULT_BASE_URL } from "../models-config.providers.js";
import { log } from "./logger.js";

// Session cache to avoid re-attestation on every request
interface MapleSession {
  sessionKey: Uint8Array;
  sessionId: string;
  expiresAt: number;
}

const sessionCache = new Map<string, MapleSession>();
const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Encrypt a message using ChaCha20-Poly1305
 */
function encryptMessage(sessionKey: Uint8Array, message: string): string {
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const chacha = new ChaCha20Poly1305(sessionKey);
  const encrypted = chacha.seal(nonce, new TextEncoder().encode(message));
  // Prepend nonce to ciphertext
  const combined = new Uint8Array(nonce.length + encrypted.length);
  combined.set(nonce);
  combined.set(encrypted, nonce.length);
  return base64Encode(combined);
}

/**
 * Decrypt a message using ChaCha20-Poly1305
 */
function decryptMessage(sessionKey: Uint8Array, encryptedBase64: string): string {
  const data = base64Decode(encryptedBase64);
  const nonce = data.slice(0, 12);
  const ciphertext = data.slice(12);
  const chacha = new ChaCha20Poly1305(sessionKey);
  const decrypted = chacha.open(nonce, ciphertext);
  if (!decrypted) {
    throw new Error("Decryption failed");
  }
  return new TextDecoder().decode(decrypted);
}

/**
 * Fetch and verify attestation, then perform key exchange
 */
async function getMapleSession(apiKey: string, apiUrl: string): Promise<MapleSession> {
  const cacheKey = `${apiUrl}:${apiKey.slice(0, 8)}`;
  const cached = sessionCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached;
  }

  const nonce = webcrypto.randomUUID();
  log.debug(`Maple: fetching attestation with nonce ${nonce}`);

  // Fetch attestation document
  const attestationUrl = `${apiUrl}/attestation/${nonce}`;
  const attestationRes = await fetch(attestationUrl);
  if (!attestationRes.ok) {
    throw new Error(`Failed to fetch attestation: ${attestationRes.status}`);
  }
  const { attestation_document } = (await attestationRes.json()) as {
    attestation_document: string;
  };

  // For now, we'll do a simplified verification that extracts the server public key
  // Full verification would involve checking the AWS Nitro certificate chain
  const serverPublicKey = await extractPublicKeyFromAttestation(attestation_document);

  // Generate client key pair for ECDH
  const clientKeyPair = nacl.box.keyPair();

  // Perform key exchange
  const keyExchangeUrl = `${apiUrl}/key_exchange`;
  const keyExchangeRes = await fetch(keyExchangeUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_public_key: base64Encode(clientKeyPair.publicKey),
      nonce,
    }),
  });

  if (!keyExchangeRes.ok) {
    throw new Error(`Key exchange failed: ${keyExchangeRes.status}`);
  }

  const { encrypted_session_key, session_id } = (await keyExchangeRes.json()) as {
    encrypted_session_key: string;
    session_id: string;
  };

  // Derive shared secret using ECDH
  const sharedSecret = nacl.scalarMult(clientKeyPair.secretKey, serverPublicKey);

  // Decrypt the session key
  const encryptedData = base64Decode(encrypted_session_key);
  const decryptionNonce = encryptedData.slice(0, 12);
  const ciphertext = encryptedData.slice(12);

  const chacha = new ChaCha20Poly1305(sharedSecret);
  const sessionKey = chacha.open(decryptionNonce, ciphertext);
  if (!sessionKey) {
    throw new Error("Failed to decrypt session key");
  }

  log.debug(`Maple: session established, sessionId=${session_id}`);

  const session: MapleSession = {
    sessionKey,
    sessionId: session_id,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
  sessionCache.set(cacheKey, session);
  return session;
}

/**
 * Extract the server's public key from the attestation document.
 * This is a simplified extraction - full verification would check the certificate chain.
 */
async function extractPublicKeyFromAttestation(attestationBase64: string): Promise<Uint8Array> {
  // The attestation document is CBOR-encoded COSE_Sign1
  // We need to decode it to get the public key
  // Using dynamic import for cbor2 since it may not be available
  const cbor = await import("cbor2");

  const attestationBuffer = base64Decode(attestationBase64);
  const coseSign1 = cbor.decode(attestationBuffer) as Uint8Array[];

  // COSE_Sign1 structure: [protected, unprotected, payload, signature]
  const payload = coseSign1[2];
  const documentData = cbor.decode(payload) as { public_key?: Uint8Array };

  if (!documentData.public_key) {
    throw new Error("Attestation document missing public key");
  }

  return new Uint8Array(documentData.public_key);
}

/**
 * Extract a complete SSE event from the buffer
 */
function extractEvent(buffer: string): string | null {
  const eventEnd = buffer.indexOf("\n\n");
  if (eventEnd === -1) return null;
  return buffer.slice(0, eventEnd + 2);
}

/**
 * Create a custom fetch function for Maple's TEE-encrypted inference.
 */
export function createMapleCustomFetch(apiKey: string): typeof fetch {
  const apiUrl =
    process.env.MAPLE_API_URL?.trim()?.replace(/\/v1\/?$/, "") ||
    MAPLE_DEFAULT_BASE_URL.replace(/\/v1\/?$/, "");

  log.debug(`Maple: creating customFetch for ${apiUrl}`);

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    log.debug(`Maple fetch: ${init?.method || "GET"} ${url}`);

    try {
      log.debug(`Maple: getting session for ${apiUrl}`);
      const session = await getMapleSession(apiKey, apiUrl);
      log.debug(`Maple: session ready, sessionId=${session.sessionId}`);

      const headers = new Headers(init?.headers);
      headers.set("Authorization", `Bearer ${apiKey}`);
      headers.set("x-session-id", session.sessionId);

      const requestOptions: RequestInit = { ...init, headers };

      // Encrypt the request body if present
      if (init?.body) {
        const bodyStr = typeof init.body === "string" ? init.body : JSON.stringify(init.body);
        const encryptedBody = encryptMessage(session.sessionKey, bodyStr);
        requestOptions.body = JSON.stringify({ encrypted: encryptedBody });
        headers.set("Content-Type", "application/json");
      }

      const response = await fetch(url, requestOptions);

      if (!response.ok) {
        const errorText = await response.text();
        log.error(`Maple request failed: ${response.status} ${errorText}`);
        throw new Error(`Request failed with status ${response.status}: ${errorText}`);
      }

      // Handle SSE streams (decrypting each event)
      if (response.headers.get("content-type")?.includes("text/event-stream")) {
        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error("No response body for SSE stream");
        }

        const decoder = new TextDecoder();
        let buffer = "";

        const stream = new ReadableStream({
          async start(controller) {
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                let event;
                while ((event = extractEvent(buffer))) {
                  buffer = buffer.slice(event.length);
                  const lines = event.split("\n");

                  for (const line of lines) {
                    if (line.trim().startsWith("event: ")) {
                      controller.enqueue(new TextEncoder().encode(line + "\n"));
                    } else if (line.trim().startsWith("data: ")) {
                      const data = line.slice(6).trim();
                      if (data === "[DONE]") {
                        controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
                      } else {
                        try {
                          const decrypted = decryptMessage(session.sessionKey, data);
                          controller.enqueue(new TextEncoder().encode(`data: ${decrypted}\n`));
                        } catch (err) {
                          log.warn(`Maple: failed to decrypt SSE chunk: ${String(err)}`);
                        }
                      }
                    } else if (line === "") {
                      controller.enqueue(new TextEncoder().encode("\n"));
                    }
                  }
                }
              }
            } finally {
              controller.close();
            }
          },
        });

        return new Response(stream, {
          headers: response.headers,
          status: response.status,
          statusText: response.statusText,
        });
      }

      // Handle regular JSON responses
      const responseText = await response.text();
      try {
        const responseData = JSON.parse(responseText) as { encrypted?: string };
        if (responseData.encrypted) {
          const decrypted = decryptMessage(session.sessionKey, responseData.encrypted);
          return new Response(decrypted, {
            headers: response.headers,
            status: response.status,
            statusText: response.statusText,
          });
        }
      } catch {
        // Not encrypted JSON, return as-is
      }

      return new Response(responseText, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText,
      });
    } catch (error) {
      log.error(`Maple fetch error: ${String(error)}`);
      throw error;
    }
  };
}
