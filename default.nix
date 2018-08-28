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

in (overrideCC stdenv gcc8).mkDerivation {
  name = "angr-deps";
  buildInputs = [
    #(stdenv.mkDerivation {
    #  name = "processor-trace";
    #  src = fetchFromGitHub {
    #    owner = "hase-project";
    #    repo = "processor-trace";
    #    rev = "10e7dd2ada2509d470bcfe32b6b35497304d4025";
    #    sha256 = "1gf4sxcrvh5jzpad6kxzy71b9m2wf1fikylx84q31kkhn4xlalms";
    #  };
    #  buildInputs = [ cmake ];
    #  cmakeFlags = ["-DSIDEBAND=ON" "-DPEVENT=ON" "-DCMAKE_BUILD_TYPE=RelWithDebInfo"];
    #  dontStrip=1;
    #})
    (stdenv.mkDerivation {
      name = "processor-trace";
      src = ./processor-trace;
      #src = fetchFromGitHub {
      #  owner = "hase-project";
      #  repo = "processor-trace";
      #  rev = "10e7dd2ada2509d470bcfe32b6b35497304d4025";
      #  sha256 = "1gf4sxcrvh5jzpad6kxzy71b9m2wf1fikylx84q31kkhn4xlalms";
      #};
      buildInputs = [ cmake ];
      cmakeFlags = ["-DSIDEBAND=ON" "-DPEVENT=ON" "-DFEATURE_ELF=ON" "-DCMAKE_BUILD_TYPE=Debug"];
      dontStrip=1;
    })
    cquery
    meson
    ninja

    #pwndbg
    linuxPackages.bcc
    bashInteractive
    #pypy27
    unicorn-emu
    git-lfs
    radare2
    openssl
    python2Packages.pyqt5
    python2Packages.virtualenv
    python2Packages.pandas
    qt5.qttools
    gdb
    pkgconfig
    valgrind

    (runCommand "musl-gcc" {} ''
      mkdir -p $out/bin
      ln -s ${musl.dev}/bin/musl-gcc $out/bin
    '')

    #(buildEnv {
    #  name = "tools";
    #  # here we only want binaries without polluting
    #  # PYTHONPATH/NIX_CFLAGS_COMPILE...
    #  paths = [ mypy python2Packages.virtualenv python2Packages.yapf ]; 
    #})
  ];
  #] ++ pypyVim;
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";

  hardeningDisable = ["all"];
}
