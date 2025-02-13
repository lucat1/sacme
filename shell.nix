let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  allowUnfree = true;
  packages = with pkgs; [
    go
  ];
}
