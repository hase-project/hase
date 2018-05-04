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
    qt5.qttools
    gdb
    # avoid polluting PYTHONPATH
    (buildEnv {
      name = "python-tools";
      paths = [ mypy python2Packages.virtualenv ]; 
    })
    (linuxPackages.perf.overrideAttrs(old: {
      patches = [ ./perf-script-sample-addr.patch ];
    }))
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
}
