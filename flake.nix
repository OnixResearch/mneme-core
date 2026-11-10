{
  description = "Mneme Rust development environment and planning checks";

  inputs = {
    # Update these revisions deliberately with the lockfile and verification.
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
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = toolchainFor pkgs;
          # Rats' selected Iced backend loads these at runtime (tiny-skia/softbuffer).
          nativeUiLibraries = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.libx11
            pkgs.libxcursor
            pkgs.libxi
            pkgs.libxkbcommon
            pkgs.libxrandr
            pkgs.wayland
          ];
        in
        {
          default = pkgs.mkShell {
            packages =
              (with pkgs; [
                rustToolchain
                nodejs_22
                git
                jq
                ripgrep
                fd
                just
                nixfmt
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
                pkgs.xorg-server
                pkgs.xvfb-run
              ];
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [
              pkgs.openssl
              pkgs.sqlite
            ]
            ++ nativeUiLibraries;
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            OPENSPEC_TELEMETRY = "0";
            shellHook = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath nativeUiLibraries}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = (rustPlatformFor pkgs).buildRustPackage {
            pname = "mneme";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = false;
            meta = {
              description = "Local knowledge workspace and durable external agent memory";
              mainProgram = "mneme";
            };
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = toolchainFor pkgs;
        in
        {
          documentation =
            pkgs.runCommand "mneme-documentation-check" { nativeBuildInputs = [ pkgs.nodejs_22 ]; }
              ''
                cp -R ${self} source
                chmod -R u+w source
                cd source
                node scripts/check-docs.mjs
                node --test scripts/test-check-docs.mjs
                touch "$out"
              '';
          loop-control =
            pkgs.runCommand "mneme-loop-control-check"
              {
                nativeBuildInputs = [
                  pkgs.nodejs_22
                  pkgs.git
                  pkgs.bash
                ];
              }
              ''
                cp -R ${self} source
                chmod -R u+w source
                cd source
                node --test scripts/test-loop-state.mjs
                touch "$out"
              '';
          # Formatting is cheap and needs no dependency closure.
          rust-format =
            pkgs.runCommand "mneme-rust-format-check" { nativeBuildInputs = [ rustToolchain ]; }
              ''
                cp -R ${self} source
                chmod -R u+w source
                cd source
                cargo fmt --all -- --check
                touch "$out"
              '';
          # Clippy and the locked workspace tests compile the real application
          # sources, including subprocess CLI and evaluation fixtures.
          rust-checks = (rustPlatformFor pkgs).buildRustPackage {
            pname = "mneme-rust-checks";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = true;
            checkPhase = ''
              cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
              cargo test --offline --locked --workspace --all-targets --all-features
            '';
            installPhase = "touch $out";
          };
        }
      );
    };
}
