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

  myPerf = linuxPackages.perf.overrideAttrs(old: {
    patches = [ ./perf-script-sample-addr.patch ];
    makeFlags = [ "LIBCLANGLLVM=1" ];

    preBuild = (old.preBuild or "") + ''
      # set by llvm -> not recognized by g++
      unset NIX_CXXSTDLIB_LINK

      # perf assumes that clang + llvm are in the same project
      EXTRA_PERFLIBS+=" -Wl,--start-group"
      for lib in ${llvmPackages_39.clang-unwrapped}/lib/*.a; do
          EXTRA_PERFLIBS+=" $lib"
      done
      EXTRA_PERFLIBS+=" -Wl,--end-group"
      export EXTRA_PERFLIBS
      echo $EXTRA_PERFLIBS
    '';


    buildInputs = linuxPackages.perf.buildInputs ++ (with llvmPackages_39; [
      llvm
      clang-unwrapped
      libclang
    ]);

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
    python2Packages.pandas
    qt5.qttools
    gdb
    # avoid polluting PYTHONPATH
    (buildEnv {
      name = "python-tools";
      paths = [ mypy python2Packages.virtualenv ]; 
    })
    myPerf
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";
}
