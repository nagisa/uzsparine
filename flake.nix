{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
        flake-utils.url = "github:numtide/flake-utils";
    };
    outputs = { self, nixpkgs, flake-utils }: let
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        package = pkgs: (pkgs.makeRustPlatform {
            rustc = pkgs.rustc;
            cargo = pkgs.cargo;
        }).buildRustPackage {
            inherit (cargoToml.package) name version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = false;
        };
        flakeForSystem = system: let
            pkgs = nixpkgs.legacyPackages.${system};
        in {
            devShell = with pkgs; mkShell {
                RUSTFLAGS = "-Clink-arg=-fuse-ld=mold";
                packages = [
                    git
                    mold-wrapped
                    rustup
                ];
            };
            packages.default = package pkgs;
        };
    in (flake-utils.lib.eachDefaultSystem (system: flakeForSystem system)) // {
        inherit package;
    };
}
