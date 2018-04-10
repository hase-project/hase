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
    # avoid propagating python3 libraries to nix-shell
    #(runCommand "pipenv" {} ''
    #  mkdir -p $out/bin
    #  ln -s ${pipenv}/bin/pipenv $out/bin/pipenv
    #'')
    (pipenv.override {
      python3Packages = python2Packages;
    })
    unicorn-emu
    git-lfs
    radare2
    openssl
    python2Packages.pyqt5
    python2
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
}
