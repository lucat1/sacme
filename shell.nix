let
  pkgs = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/7a339d87931bba829f68e94621536cad9132971a.tar.gz";
  }) {};
in pkgs.mkShell {
  packages = with pkgs; [
    go_1_19
  ];
}
