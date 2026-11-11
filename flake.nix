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
      cargoOutputHashes = {
        "dpi-0.1.1" = "sha256-pQn1lCFSJMkjUfHoggEzMHnm5k+Chnzi5JEDjahnjUA=";
        "iced-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_core-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_debug-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_futures-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_graphics-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_program-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_renderer-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_runtime-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_tiny_skia-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_widget-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "iced_winit-0.15.0-dev" = "sha256-/lR2oeQxZmyvkOLSve93qm+iQKS/j281sTW/ZAF+hBo=";
        "winit-0.30.8" = "sha256-pQn1lCFSJMkjUfHoggEzMHnm5k+Chnzi5JEDjahnjUA=";
      };
      ratsSrc = builtins.fetchTree {
        type = "git";
        url = "ssh://git@github.com/brittonr/rats.git";
        rev = "6be26efd727611b10232fb6657653ea2b15ff651";
        narHash = "sha256-DgXeyiEdHYlTf1KV77OKfDLlloEOw8qYhheXq7MIdu4=";
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
          nativeUiLibraries = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.libx11
            pkgs.libxcursor
            pkgs.libxi
            pkgs.libxkbcommon
            pkgs.libxrandr
            pkgs.wayland
          ];
          package = (rustPlatformFor pkgs).buildRustPackage {
            pname = "mneme";
            version = "0.1.0";
            src = self;
            prePatch = ''
              rm -rf vendor/rats
              mkdir -p vendor
              cp -R ${ratsSrc} vendor/rats
            '';
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = cargoOutputHashes;
            };
            buildInputs = [ pkgs.openssl pkgs.sqlite ] ++ nativeUiLibraries;
            nativeBuildInputs = [ pkgs.makeWrapper ];
            doCheck = false;
            postInstall = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
              wrapProgram $out/bin/mneme-desktop \
                --prefix LD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath nativeUiLibraries}"
            '';
            meta = {
              description = "Local knowledge workspace and durable external agent memory";
              mainProgram = "mneme";
            };
          };
        in
        {
          default = package;
          desktop = package;
        }
      );

      apps = forAllSystems (
        system:
        let
          package = self.packages.${system}.default;
        in
        {
          default = {
            type = "app";
            program = "${package}/bin/mneme-desktop";
            meta.description = "Mneme desktop notes (creates a workspace on first run)";
          };
          desktop = {
            type = "app";
            program = "${package}/bin/mneme-desktop";
            meta.description = "Mneme desktop notes";
          };
          cli = {
            type = "app";
            program = "${package}/bin/mneme";
            meta.description = "Mneme command line, MCP, and evaluation harness";
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = toolchainFor pkgs;
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
          desktop-help =
            pkgs.runCommand "mneme-desktop-help-check" { }
              ''
                export HOME="$TMPDIR/home"
                mkdir -p "$HOME"
                ${self.packages.${system}.default}/bin/mneme-desktop --help > help.txt
                grep -q "Usage: mneme-desktop" help.txt
                grep -q -- "--workspace <DIR>" help.txt
                ${self.packages.${system}.default}/bin/mneme-desktop --version > version.txt
                grep -q "mneme-desktop" version.txt
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
            prePatch = ''
              rm -rf vendor/rats
              mkdir -p vendor
              cp -R ${ratsSrc} vendor/rats
            '';
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = cargoOutputHashes;
            };
            buildInputs = [ pkgs.openssl pkgs.sqlite ] ++ nativeUiLibraries;
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
