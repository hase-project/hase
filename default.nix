with import <nixpkgs> {};
let
  pypyVim = lib.optional (myvim != null) (myvim.override {
    configure = {
      customRC = ''
          if filereadable($HOME . "/.vimrc")
            source ~/.vimrc
          endif
      '';
      packages.nixbundle = myVimBundle { python = pypy27;};
    };
  });
in stdenv.mkDerivation {
  name = "env";
  buildInputs = [
    bashInteractive
    #pypy27
    unicorn-emu
    git-lfs
    radare2
    openssl
    python2Packages.pyqt5
    python2Packages.virtualenv
    python2
    qt5.qttools
    gdb
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
}
