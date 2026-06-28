{
  description = "Barebones development environment for sdb-rs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.fenix.url = "github:nix-community/fenix";
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    { self, nixpkgs, fenix }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      # Nightly toolchain that includes the miri component + rust-src.
      # cargo miri setup builds a sysroot, so rust-src is required.
      miriToolchain = fenix.packages.${system}.latest.withComponents [
        "cargo"
        "rustc"
        "miri"
        "rust-src"
        "llvm-tools"
      ];
    in
    {
      devShells.x86_64-linux = {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            gdb
            rust-analyzer
            clippy
            git
            cmake
            pkg-config
            libdwarf
          ];
          shellHook = ''
            echo "Welcome to the sdb-rs Development Environment"
          '';
          env.RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };

        # Dedicated shell for running Miri on the computational unsafe code.
        # Enter with: nix develop .#miri
        miri = pkgs.mkShell {
          buildInputs = [ miriToolchain ];
          shellHook = ''
            echo "sdb-rs Miri shell"
            cargo miri --version 2>/dev/null || true
          '';
        };
      };
    };
}
