{
  stdenv,
  lib,

  dig,
  dnsmasq,
  makeWrapper,
  python3,
  which,
  fetchFromGitHub,
}:

stdenv.mkDerivation {
  name = "markasoftware-dns-pentesting";
  src = fetchFromGitHub {
    owner = "markasoftware";
    repo = "dns-pentesting";
    rev = "d45a030bb19fc1737df908a9e7bc8ed90bece174";
    hash = "sha256-AfKsRnbPEh+jwh0GWXw/9zlUKUDfPhXQ9ZmiZiI9m/o=";
  };

  nativeBuildInputs = [
    makeWrapper
  ];

  buildInputs = [
    dig
    python3
    which
  ];

  checkInputs = [
    dnsmasq
  ];

  checkPhase = "bash test-all.sh";

  # doCheck = true;

  installPhase = ''
    mkdir -p "$out/bin"
    cp *.py "$out"
    for executable in "$out"/dns_*.py; do
        filename="$(basename "$executable")"
        ln -s "$executable" "$out/bin/''${filename%.py}"
    done
  '';

  # wrapProgram goes through symlinks :::|||
  postFixup = ''
    for executable in "$out"/dns_*; do
        wrapProgram "$executable" --set PATH ${lib.makeBinPath [ dig ]}
    done
  '';
}
