{
  description = "Moltbot development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Node.js 22+ as required by package.json engines
            nodejs_22
            
            # Package manager
            pnpm
            
            # Bun (also supported for dev/scripts)
            bun
            
            # Build tools
            typescript
            node-gyp
            
            # Native dependencies for node-gyp builds
            python3
            gnumake
            gcc
            pkg-config
            
            # For sharp (image processing) - need full dev libs
            vips
            glib
            libffi
            
            # Git
            git
            
            # GitHub CLI (used in workflows)
            gh
          ];

          shellHook = ''
            echo "Moltbot dev environment"
            echo "Node: $(node --version)"
            echo "pnpm: $(pnpm --version)"
            echo "Bun: $(bun --version)"
            echo ""
            echo "Run 'pnpm install' to install dependencies"
            echo "Run 'pnpm build' to build TypeScript"
            echo "Run 'pnpm test' to run tests"
          '';

          # Environment variables for native builds
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.vips
            pkgs.glib
            pkgs.libffi
          ];
          
          PKG_CONFIG_PATH = "${pkgs.vips.dev}/lib/pkgconfig:${pkgs.glib.dev}/lib/pkgconfig:${pkgs.libffi.dev}/lib/pkgconfig";
        };
      }
    );
}
