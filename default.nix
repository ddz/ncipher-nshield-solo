{ pkgs ? import <nixpkgs> {}, kernel ? pkgs.linuxPackages.kernel }:
let
  v = kernel.modDirVersion;
in pkgs.stdenv.mkDerivation {
  pname = "nshield-solo";
  version = "0.20191220.1";

  src = ./.;

  nativeBuildInputs = kernel.moduleBuildDependencies;

  buildPhase = ''
    make -C ${kernel.dev}/lib/modules/${v}/build M=$PWD modules
  '';

  installPhase = ''
    mkdir -p $out/lib/modules/${v}/extra
    cp nshield_solo.ko $out/lib/modules/${v}/extra/
  '';
}
