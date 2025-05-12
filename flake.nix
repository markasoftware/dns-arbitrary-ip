{
  description = "DNS pentesting tools";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let lib = nixpkgs.lib;
        dns-programs = import ./dns-programs.nix;
    in flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in rec {
        packages = rec {
          markasoftware-dns-pentesting = pkgs.callPackage (import ./package.nix) {};
          default = markasoftware-dns-pentesting;
        };

        apps = dns-programs.each (program: {
          type = "app";
          program = "${packages.default.out}/bin/${program.binName}";
        });
      }
    ) // {
      nixosModules = {config, pkgs, lib, ...}:
        dns-programs.each (program: {
          options = {
            services.${program.attrName} = {
              enable = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = "Enable ${program.binName} systemd service";
              };

              cliArgs = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [];
                description = "extra CLI arguments";
              };

              package = lib.mkPackageOption pkgs "${program.attrName}" {};
            };
          };

          config = let cfg = config.services.${program.attrName};
                   in lib.mkIf cfg.enable {
                     systemd.services.${program.attrName} = {
                       description = "DNS pentesting tool: ${program.binName}";
                       after = ["network.target"];
                       wantedBy = ["multi-user.target"];
                       serviceConfig = {
                         Restart = "on-failure";
                         ExecStart = "${cfg.package}/bin/${program.binName} ${lib.escapeShellArgs cfg.cliArgs}";
                       };
                     };
                   };
        });
    };
}
