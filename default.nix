with import <nixpkgs> {};
(overrideCC stdenv gcc8).mkDerivation {
  name = "angr-deps";
  buildInputs = [
    (stdenv.mkDerivation {
      name = "processor-trace";
      src = fetchFromGitHub {
        owner = "hase-project";
        repo = "processor-trace";
        rev = "10e7dd2ada2509d470bcfe32b6b35497304d4025";
        sha256 = "1gf4sxcrvh5jzpad6kxzy71b9m2wf1fikylx84q31kkhn4xlalms";
      };
      nativeBuildInputs = [ cmake ];
      cmakeFlags = ["-DCMAKE_BUILD_TYPE=RelWithDebInfo"];
      dontStrip=1;
    })
    meson
    ninja

    linuxPackages.bcc
    bashInteractive
    unicorn-emu
    git-lfs
    openssl
    python2Packages.pyqt5
    python2Packages.virtualenv
    python2Packages.pandas
    qt5.qttools
    pkgconfig

    (runCommand "musl-gcc" {} ''
      mkdir -p $out/bin
      ln -s ${musl.dev}/bin/musl-gcc $out/bin
    '')
  ];
  PYTHON="python2";
  SOURCE_DATE_EPOCH="1523278946";
  # better not to use tmpfs
  TMPDIR="/tmp";

  hardeningDisable = ["all"];
}
