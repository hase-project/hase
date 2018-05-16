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

  myLinuxPackages = linuxPackages;
  myLinux = linux;

  myPerf = myLinuxPackages.perf.overrideAttrs(old: {
    patches = [ 
      ./perf-script-sample-addr.patch
      # kernel source path
      (fetchpatch {
        url = "https://github.com/Mic92/linux/commit/fdf56d6b10f545f25cae757c8fbeb08cb9d396c3.patch";
        sha256 = "1qc50wagz3snsb6ql3wjgnyqf8lpyzqzrg7nvgk97965cgmly8vy";
      })
    ];
    NIX_CFLAGS_COMPILE = " -DKERNELDIR=\"${myLinux.dev}/\" ";
    makeFlags = [ "LIBCLANGLLVM=1" ];

    preBuild = (old.preBuild or "") + ''
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
  name = "angr-deps";
  buildInputs = [
    linuxPackages.bcc
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
    (buildEnv {
      name = "tools";
      # here we only want binaries without polluting
      # PYTHONPATH/NIX_CFLAGS_COMPILE...
      paths = [ mypy python2Packages.virtualenv python2Packages.yapf musl.dev ]; 
    })
    myPerf
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";

  hardeningDisable = ["all"];
}
