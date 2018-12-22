with import <nixpkgs> {};
let
  processor-trace = (stdenv.mkDerivation rec {
    name = "processor-trace-${version}";
    version = "2.0";
    src = fetchFromGitHub {
      owner = "01org";
      repo = "processor-trace";
      rev = "v${version}";
      sha256 = "1qhrsycxqjm9xmhi3zgkq9shzch54dp4nc83d1gk5xs0287wsw5p";
    };
    nativeBuildInputs = [ cmake ];
    cmakeFlags = ["-DCMAKE_BUILD_TYPE=RelWithDebInfo"];
    dontStrip=1;
  });

  musl-gcc = (runCommand "musl-gcc" {} ''
    mkdir -p $out/bin
    ln -s ${musl.dev}/bin/musl-gcc $out/bin
  '');
in

stdenv.mkDerivation {
  name = "hase-deps";
  buildInputs = [
    bashInteractive
    processor-trace
    git-lfs
    openssl
    # cannot be installed with pip
    #python36Packages.pyqt5
    # does not find libffi when installed with pip
    #python36Packages.cffi
    musl-gcc
    pypy3
    (pypy3.pkgs.pip.overrideAttrs (old: rec {
      name = "pip-${version}";
      version = "18.1";
      src = pypy3.pkgs.fetchPypi {
        inherit (old) pname;
        inherit version;
        sha256 = "188fclay154s520n43s7cxxlhdaiysvxf19zk8vr1xbyjyyr58n0";
      };
    }))

    qt5.qttools
    pkgconfig
    glibcLocales
  ];
  shellHook = ''
    export PATH=$PATH:${mypy}/bin:${python3.pkgs.flake8}/bin
  '';
  PYTHON="${python2.interpreter}";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";

  hardeningDisable = ["all"];
}
