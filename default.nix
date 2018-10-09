with import <nixpkgs> {};
let
  pip_18_1 = (python3Packages.pip.overrideAttrs (old: rec {
    name = "pip-${version}";
    version = "18.1";
    src = python3Packages.fetchPypi {
      inherit (old) pname;
      inherit version;
      sha256 = "188fclay154s520n43s7cxxlhdaiysvxf19zk8vr1xbyjyyr58n0";
    };
  }));

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

(overrideCC stdenv gcc7).mkDerivation {
  name = "angr-deps";
  buildInputs = [
    meson
    ninja

    processor-trace

    linuxPackages.bcc
    bashInteractive
    unicorn-emu
    git-lfs
    openssl
    python3Packages.pyqt5
    pip_18_1
    musl-gcc

    python3Packages.virtualenv
    python3Packages.pandas
    qt5.qttools
    pkgconfig

  ];
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";

  hardeningDisable = ["all"];
}
