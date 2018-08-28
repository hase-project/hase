with import <nixpkgs> {};
(overrideCC stdenv gcc7).mkDerivation {
  name = "angr-deps";
  buildInputs = [
    (stdenv.mkDerivation rec {
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
