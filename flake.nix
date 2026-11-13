{
  description = "Mneme Core: standalone Rust libraries, verification checks, and a development shell";

  inputs = {
    # The pinned Octet runner and Dylint library are development tools only.
    octet.url = "git+ssh://git@github.com/OnixResearch/octet?rev=2bdd581980eef7f6ec8363ffa20ab9f3c798c9ee";
    # Pinned Charon/Aeneas pair and the Rust nightly Charon is built against.
    aeneas.url = "github:AeneasVerif/aeneas/505b6ca35217e7be5c96c3e2f8045edfbdf47291";
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs/ac588ef1c914865dad517b337ea0eb9694a4021c";
    rust-overlay = {
      url = "github:oxalica/rust-overlay/89750a2ef1c6a44db9f4251b16c23deffdcfddff";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      octet,
      aeneas,
      crane,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      toolchainFor = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatformFor =
        pkgs:
        pkgs.makeRustPlatform {
          cargo = toolchainFor pkgs;
          rustc = toolchainFor pkgs;
        };
      # The pinned Lean release is needed only by the kernel-proof dev workflow.
      # Its upstream bytes are fixed by hash; Nix patches only the ELF interpreter.
      leanReleaseFor =
        pkgs:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "mneme-lean-release";
          version = "4.35.0";
          src = pkgs.fetchurl {
            url = "https://github.com/leanprover/lean4/releases/download/v4.35.0/lean-4.35.0-linux.tar.zst";
            hash = "sha256-colZekRUMkbJInuMrlAXZ+CVzhf21Ei5X8So3Jcmj20=";
          };
          nativeBuildInputs = [
            pkgs.zstd
            pkgs.autoPatchelfHook
          ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          dontConfigure = true;
          dontBuild = true;
          dontStrip = true;
          installPhase = ''
            mkdir -p "$out"
            cp -r ./. "$out/"
          '';
        };
      hasProofTools = system: system == "x86_64-linux";
      proofToolsFor =
        system: pkgs:
        pkgs.lib.optionals (hasProofTools system) [
          aeneas.packages.${system}.aeneas
          aeneas.packages.${system}.charon
          (leanReleaseFor pkgs)
        ];
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = toolchainFor pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.nodejs_22
              pkgs.git
              pkgs.just
              pkgs.nixfmt
              octet.packages.${system}.cargo-octet
              pkgs.scryer-prolog
            ]
            ++ proofToolsFor system pkgs;
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            MNEME_SCRYER_PROLOG = "${pkgs.scryer-prolog}/bin/scryer-prolog";
            shellHook = pkgs.lib.optionalString (hasProofTools system) ''
              # Charon was built with this exact nightly; the proof gate places
              # it before the regular stable toolchain when extracting the kernel.
              export MNEME_EXTRACTION_TOOLCHAIN_BIN="${aeneas.inputs.charon.packages.${system}.rustToolchain}/bin"
            '';
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = toolchainFor pkgs;
          rustChecks = (rustPlatformFor pkgs).buildRustPackage {
            pname = "mneme-core-rust-checks";
            version = "0.1.0";
            src = self;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            nativeBuildInputs = [ rustToolchain ];
            buildInputs = [ pkgs.scryer-prolog ];
            doCheck = true;
            cargoBuildFlags = [
              "--workspace"
              "--all-features"
              "--lib"
            ];
            MNEME_SCRYER_PROLOG = "${pkgs.scryer-prolog}/bin/scryer-prolog";
            checkPhase = ''
              cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
              cargo test --offline --locked --workspace --all-targets --all-features --no-fail-fast
              cargo test --offline --locked --workspace --doc --all-features
            '';
            installPhase = ''
              mkdir -p "$out"
            '';
          };
          rustFormat =
            pkgs.runCommand "mneme-core-rust-format-check"
              {
                nativeBuildInputs = [ rustToolchain ];
              }
              ''
                cp -R ${self}/. source
                chmod -R u+w source
                cd source
                cargo fmt --all -- --check
                touch "$out"
              '';
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          octetVendor = craneLib.vendorCargoDeps { cargoLock = ./Cargo.lock; };
          octetWorkspace = octet.lib.mkConsumerCheck {
            inherit system;
            src = self;
            cargoExtraArgs = "--all-targets --all-features --ignore-rust-version --offline";
            cargoLock = ./Cargo.lock;
            buildInputs = [ ];
          };
          octetAll =
            pkgs.runCommand "mneme-core-octet-all-check"
              {
                nativeBuildInputs = [
                  rustToolchain
                  octet.packages.${system}.cargo-octet
                ];
              }
              ''
                mkdir source
                cp -R ${self}/. source/
                chmod -R u+w source
                cd source
                cp dylint-all.toml dylint.toml
                export HOME="$PWD/home"
                mkdir -p "$HOME"
                export CARGO_HOME="$PWD/.cargo-home"
                mkdir -p "$CARGO_HOME"
                cp ${octetVendor}/config.toml "$CARGO_HOME/config.toml"
                cargo-octet check \
                  --workspace --baseline octet-baseline.json \
                  -- --all-targets --all-features --ignore-rust-version --offline
                touch "$out"
              '';
        in
        {
          rust = rustChecks;
          rust-format = rustFormat;
          octet = octetWorkspace;
          octet-all = octetAll;
        }
      );
    };
}
