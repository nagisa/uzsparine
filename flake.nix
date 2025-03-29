{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
        flake-utils.url = "github:numtide/flake-utils";
    };
    outputs = { self, nixpkgs, flake-utils }: let
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        package = pkgs: pkgs.rustPlatform.buildRustPackage {
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
    in (flake-utils.lib.eachDefaultSystem (system: flakeForSystem system)) // rec {
        overlay = final: prev: { uzparine = package final; };
        nixosModules.default = { config, lib, pkgs, utils, ... }:
        let
            cfg = config.services.uzparine;
        in with lib; {
            options.services.uzparine = {
                enable = mkEnableOption "Enable the uzparine service for gate2mqtt proxy.";
                package = mkOption {
                    description = "The uzparine package to use";
                    type = types.package;
                    default = pkgs.uzparine;
                };
                flags = mkOption {
                    description = ''uzparine CLI flags to pass into the service.'';
                    default = { };
                    type = types.listOf types.str;
                };
            };

            config = mkIf cfg.enable {
                nixpkgs.overlays = [ overlay ];
                systemd.services.uzparine = {
                    description = "uzparine gate2mqtt gate control proxy";
                    wants = [ "network.target" ];
                    wantedBy = [ "multi-user.target" ];
                    serviceConfig = {
                        Restart = "on-failure";
                        ExecStart = utils.escapeSystemdExecArgs ([
                            "${cfg.package}/bin/uzparine"
                        ] ++ cfg.flags);
                    };
                };
            };
        };

    };
}
