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
    (stdenv.mkDerivation {
      name = "xed";

      src = fetchFromGitHub {
        owner = "intelxed";
        repo = "xed";
        rev = "9c6867252545d5a696dda0ca2d622901dcee4aa8";
        sha256 = "0pzq3xxq56sp207n8sv5slsns5cjip8xl34fyydvi3ivsj8h3kyr";
      };

      installPhase = ''
        python ./mfile.py install --shared --install-dir=$out 
        ln -s $out/include/xed/* $out/include
        rm -r $out/{mbuild,misc,LICENSE,examples}
			'';
      buildInputs = [
        (python.pkgs.buildPythonPackage {
          name = "mbuild";
          src = fetchFromGitHub {
            owner = "intelxed";
            repo = "mbuild";
            rev = "1651029643b2adf139a8d283db51b42c3c884513";
            sha256 = "1hdrzdyldszr4czfyw45niza4dyzbc2g14yskrz1c7fjhb6g4f6p";
          };
        })
      ];
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
    python2Packages.pandas
    qt5.qttools
    gdb
    pkgconfig
    valgrind
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
