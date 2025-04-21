{
  description = "nShield Solo, Solo+, and Solo XC PCI HSM Linux kernel driver";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      nShieldSolo = pkgs.callPackage ./default.nix { } ;
    in
    {
      packages.x86_64-linux.default = nShieldSolo;

      nixosModules.default = {
        boot.extraModulePackages = [ nShieldSolo ];
        boot.kernelModules = [ "nshield_solo" ];
    };
  };
}
