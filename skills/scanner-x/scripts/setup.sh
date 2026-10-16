#!/usr/bin/env bash
# Install the scanners Scanner-X uses: gitleaks (secrets), semgrep (code), osv-scanner
# (dependencies for Python, Java, Rust, Go, ...). Already-installed tools are skipped.
#
#   setup.sh           install whatever is missing
#   setup.sh --check   only report what's installed (exit 1 if something is missing)
#
# Never uses sudo. With Homebrew: `brew install`. Otherwise: semgrep via pipx (or
# pip --user), and gitleaks / osv-scanner as official release binaries in
# ~/.scanner-x/bin, which the Scanner-X CLI checks automatically.
set -euo pipefail

GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-2.0.0}"
SCANNER_X_HOME="${SCANNER_X_HOME:-$HOME/.scanner-x}"
BIN="$SCANNER_X_HOME/bin"
TOOLS=(gitleaks semgrep osv-scanner)

where() {
  if command -v "$1" >/dev/null 2>&1; then command -v "$1"
  elif [ -x "$BIN/$1" ]; then echo "$BIN/$1"
  else return 1
  fi
}

report() {
  local missing=0
  for t in "${TOOLS[@]}"; do
    if p=$(where "$t"); then echo "  ok       $t ($p)"; else echo "  missing  $t"; missing=1; fi
  done
  return $missing
}

if [ "${1:-}" = "--check" ]; then
  echo "Scanner-X scanners:"
  report
  exit $?
fi

missing=()
for t in "${TOOLS[@]}"; do where "$t" >/dev/null || missing+=("$t"); done
if [ ${#missing[@]} -eq 0 ]; then
  echo "All scanners are installed:"; report; exit 0
fi
echo "Installing: ${missing[*]}"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *)
    echo "Unsupported OS ($(uname -s)). On Windows, run Scanner-X inside WSL (Ubuntu) and run this script there." >&2
    exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) gl_arch=x64; osv_arch=amd64 ;;
  arm64|aarch64) gl_arch=arm64; osv_arch=arm64 ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else echo "Need curl or wget to download $1" >&2; return 1
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

failed=()

if command -v brew >/dev/null 2>&1; then
  # Homebrew packages exist for all three tools.
  brew install "${missing[@]}" || failed+=("${missing[@]}")
else
  mkdir -p "$BIN"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

  for t in "${missing[@]}"; do
    case "$t" in
      semgrep)
        if command -v pipx >/dev/null 2>&1; then pipx install semgrep || failed+=(semgrep)
        elif command -v python3 >/dev/null 2>&1; then python3 -m pip install --user semgrep || failed+=(semgrep)
        else echo "semgrep needs Python 3 (pipx or pip)." >&2; failed+=(semgrep)
        fi
        # pipx / pip --user put scripts in ~/.local/bin, which is often not on PATH. Link both
        # entry points (semgrep runs pysemgrep via PATH) where Scanner-X looks.
        if ! command -v semgrep >/dev/null 2>&1; then
          for exe in semgrep pysemgrep; do
            [ -x "$HOME/.local/bin/$exe" ] && ln -sf "$HOME/.local/bin/$exe" "$BIN/$exe"
          done
        fi ;;
      gitleaks)
        base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
        archive="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
        if fetch "$base/$archive" "$tmp/$archive" && fetch "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" "$tmp/sums.txt"; then
          expected=$(grep " $archive\$" "$tmp/sums.txt" | cut -d' ' -f1 || true)
          if [ -n "$expected" ] && [ "$expected" = "$(sha256 "$tmp/$archive")" ]; then
            tar -xzf "$tmp/$archive" -C "$tmp" gitleaks && mv "$tmp/gitleaks" "$BIN/gitleaks" && chmod +x "$BIN/gitleaks"
          else
            echo "gitleaks checksum mismatch; not installed." >&2; failed+=(gitleaks)
          fi
        else
          failed+=(gitleaks)
        fi ;;
      osv-scanner)
        url="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${os}_${osv_arch}"
        if fetch "$url" "$tmp/osv-scanner"; then
          mv "$tmp/osv-scanner" "$BIN/osv-scanner" && chmod +x "$BIN/osv-scanner"
        else
          failed+=(osv-scanner)
        fi ;;
    esac
  done
fi

echo; echo "Scanner-X scanners:"
report || true
# Whatever the installers said, trust only what can actually be found now.
for t in "${TOOLS[@]}"; do
  if ! where "$t" >/dev/null && [[ " ${failed[*]} " != *" $t "* ]]; then failed+=("$t"); fi
done
if [ ${#failed[@]} -gt 0 ]; then
  echo
  echo "Could not install: ${failed[*]}. Install manually:" >&2
  echo "  macOS:  brew install ${failed[*]}" >&2
  echo "  Linux:  pipx install semgrep; gitleaks and osv-scanner binaries from their GitHub releases pages" >&2
  exit 1
fi
if [ -d "$BIN" ] && ls "$BIN" >/dev/null 2>&1 && [ -n "$(ls -A "$BIN" 2>/dev/null)" ]; then
  echo
  echo "Binaries in $BIN are found by Scanner-X automatically."
  echo "To use them in your own shell too: export PATH=\"\$PATH:$BIN\""
fi
