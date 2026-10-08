{ pkgs ? import <nixpkgs> {} }:

let
  # Import the flake to get the package
  flake = builtins.getFlake "git+file://${toString ./.}";
  package = flake.packages.${pkgs.system}.default;
in
package