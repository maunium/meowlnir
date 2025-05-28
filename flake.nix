{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
        flake-utils.url = "github:numtide/flake-utils";
    };

    outputs = { nixpkgs, flake-utils, ... }:
        flake-utils.lib.eachDefaultSystem (system: let
            pkgs = import nixpkgs {
                inherit system;
                config.permittedInsecurePackages = [
                    "olm-3.2.16"
                ];
            };
        in {
            devShells.default = pkgs.mkShell {
                packages = with pkgs; [
                    go_1_23
                    olm
                ];
            };
        });
}
