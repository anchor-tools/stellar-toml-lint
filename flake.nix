{
  description = "stellar-toml-lint - Offline SEP-1 linter for stellar.toml";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs, nixpkgs-darwin }:
    let
      buildPackage = system: pkgs:
        let
          npmPackage = pkgs.buildNpmPackage {
            pname = "stellar-toml-lint";
            version = "0.1.0";
            src = self;
            doCheck = false;
            installFlags = [ "--ignore-scripts" ];
npmDepsHash = "sha256-W00RXqfBukJRZO4hph8dLn1IaDOQKP3iNWmNcQOuhc4=";
            nativeBuildInputs = with pkgs; [
              nodejs_22
              python3
              pkg-config
              libtool
              automake
              autoconf
              gnumake
              gcc
              ccache
              makeWrapper
            ];
            postInstall = ''
              makeWrapper "${pkgs.nodejs_22}/bin/node" "$out/bin/stellar-toml-lint" \
                --add-flags "$out/lib/node_modules/stellar-toml-lint/dist/cli.js"
            '';
          };
        in {
          packages.default = npmPackage;
          apps.default = { type = "app"; program = "${npmPackage}/bin/stellar-toml-lint"; };
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [ nodejs_22 npm git ];
            shellHook = ''
              export PATH="${npmPackage}/bin:$PATH"
              echo "stellar-toml-lint development environment ready"
              echo "Run 'stellar-toml-lint --help' to get started"
            '';
          };
          legacyPackages.stellar-toml-lint = npmPackage;
        };
      pkgsFor = system: import nixpkgs { inherit system; config.allowUnfree = true; };
      darwinPkgsFor = system: import nixpkgs-darwin { inherit system; config.allowUnfree = true; };
      mkSystem = system: pkgs: buildPackage system pkgs;
    in
      {
        packages.x86_64-linux = (mkSystem "x86_64-linux" (pkgsFor "x86_64-linux")).packages;
        packages.aarch64-linux = (mkSystem "aarch64-linux" (pkgsFor "aarch64-linux")).packages;
        packages.x86_64-darwin = (mkSystem "x86_64-darwin" (darwinPkgsFor "x86_64-darwin")).packages;
        apps.x86_64-linux = (mkSystem "x86_64-linux" (pkgsFor "x86_64-linux")).apps;
        apps.aarch64-linux = (mkSystem "aarch64-linux" (pkgsFor "aarch64-linux")).apps;
        apps.x86_64-darwin = (mkSystem "x86_64-darwin" (darwinPkgsFor "x86_64-darwin")).apps;
        devShells.x86_64-linux = (mkSystem "x86_64-linux" (pkgsFor "x86_64-linux")).devShells;
        devShells.aarch64-linux = (mkSystem "aarch64-linux" (pkgsFor "aarch64-linux")).devShells;
        devShells.x86_64-darwin = (mkSystem "x86_64-darwin" (darwinPkgsFor "x86_64-darwin")).devShells;
        legacyPackages.x86_64-linux = (mkSystem "x86_64-linux" (pkgsFor "x86_64-linux")).legacyPackages;
        legacyPackages.aarch64-linux = (mkSystem "aarch64-linux" (pkgsFor "aarch64-linux")).legacyPackages;
        legacyPackages.x86_64-darwin = (mkSystem "x86_64-darwin" (darwinPkgsFor "x86_64-darwin")).legacyPackages;
      };
}