/**
 * Maple TEE-encrypted embedding provider using nomic-embed-text
 */
import { requireApiKey, resolveApiKeyForProvider } from "../agents/model-auth.js";
import { createMapleCustomFetch } from "../agents/pi-embedded-runner/maple-fetch.js";
import { MAPLE_DEFAULT_BASE_URL } from "../agents/models-config.providers.js";
import type { EmbeddingProvider, EmbeddingProviderOptions } from "./embeddings.js";

export type MapleEmbeddingClient = {
  baseUrl: string;
  model: string;
  customFetch: typeof fetch;
};

export const DEFAULT_MAPLE_EMBEDDING_MODEL = "nomic-embed-text";

export async function createMapleEmbeddingProvider(
  options: EmbeddingProviderOptions,
): Promise<{ provider: EmbeddingProvider; client: MapleEmbeddingClient }> {
  const client = await resolveMapleEmbeddingClient(options);
  const url = `${client.baseUrl.replace(/\/$/, "")}/embeddings`;

  const embed = async (input: string[]): Promise<number[][]> => {
    if (input.length === 0) return [];
    const res = await client.customFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: client.model, input }),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`maple embeddings failed: ${res.status} ${text}`);
    }
    const payload = (await res.json()) as {
      data?: Array<{ embedding?: number[] }>;
    };
    const data = payload.data ?? [];
    return data.map((entry) => entry.embedding ?? []);
  };

  return {
    provider: {
      id: "maple",
      model: client.model,
      embedQuery: async (text) => {
        const [vec] = await embed([text]);
        return vec ?? [];
      },
      embedBatch: embed,
    },
    client,
  };
}

export async function resolveMapleEmbeddingClient(
  options: EmbeddingProviderOptions,
): Promise<MapleEmbeddingClient> {
  const remote = options.remote;
  const remoteApiKey = remote?.apiKey?.trim();
  const remoteBaseUrl = remote?.baseUrl?.trim();

  const apiKey = remoteApiKey
    ? remoteApiKey
    : requireApiKey(
        await resolveApiKeyForProvider({
          provider: "maple",
          cfg: options.config,
          agentDir: options.agentDir,
        }),
        "maple",
      );

  const providerConfig = options.config.models?.providers?.maple;
  const baseUrl =
    remoteBaseUrl ||
    providerConfig?.baseUrl?.trim() ||
    process.env.MAPLE_API_URL?.trim() ||
    MAPLE_DEFAULT_BASE_URL;

  const model = options.model?.trim() || DEFAULT_MAPLE_EMBEDDING_MODEL;
  const customFetch = createMapleCustomFetch(apiKey);

  return { baseUrl, model, customFetch };
}
