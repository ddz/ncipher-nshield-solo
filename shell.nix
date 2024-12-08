let
  pkgs = import <nixpkgs> { };
in
(pkgs.buildFHSEnv {
  name = "linux-dev-fhs-env";
  targetPkgs = pkgs: with pkgs; [
    gcc
    gnumake
    linux.dev
  ];
}).env
