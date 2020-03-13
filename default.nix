{ pkgs ? import <nixpkgs> {

  overlays = [
    (import ../../nix-community/poetry2nix/overlay.nix)
  ];

} }:

let

  overrides = import ./overrides.nix { inherit pkgs; };

in pkgs.poetry2nix.mkPoetryApplication {
  projectDir = ./.;
  overrides = pkgs.poetry2nix.overrides.withDefaults(overrides);
}
