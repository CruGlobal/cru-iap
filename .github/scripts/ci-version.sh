#!/usr/bin/env bash
# Prints the toolchain version a CI matrix leg should install.
#
#   ci-version.sh <ruby|node|python|go|rust> <min|latest>
#
# `min` is read from the package's own manifest, so raising a floor is a
# manifest edit alone: the job stays "Ruby (min)", which is the name the
# ruleset requires (cru-terraform github/CruGlobal/repos/cru-iap). `latest`
# is the setup action's own moving alias.
set -euo pipefail

lang=$1
leg=$2
root=$(git rev-parse --show-toplevel)

if [ "$leg" = latest ]; then
  case $lang in
    ruby) echo ruby ;;
    node) echo "lts/*" ;;
    python) echo 3.x ;;
    go | rust) echo stable ;;
    *) echo "unknown language: $lang" >&2; exit 1 ;;
  esac
  exit 0
fi

if [ "$leg" != min ]; then
  echo "unknown leg: $leg (want min or latest)" >&2
  exit 1
fi

case $lang in
  ruby) version=$(sed -n 's/.*required_ruby_version = ">= *\([0-9.]*\)"$/\1/p' "$root/cru_iap.gemspec") ;;
  node) version=$(jq -r '.engines.node' "$root/package.json" | sed -n 's/^>= *\([0-9.]*\)$/\1/p') ;;
  python) version=$(sed -n 's/^requires-python = ">= *\([0-9.]*\)"$/\1/p' "$root/pyproject.toml") ;;
  go) version=$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$root/go.mod") ;;
  rust) version=$(sed -n 's/^rust-version = "\([0-9.]*\)"$/\1/p' "$root/rust/Cargo.toml") ;;
  *) echo "unknown language: $lang" >&2; exit 1 ;;
esac

# A floor written some other way (`^20 || ^22`, `~> 3.2`) must fail loudly
# rather than install whatever an empty version string resolves to.
if ! [[ $version =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
  echo "could not read a plain >= floor for $lang (got '$version')" >&2
  exit 1
fi
echo "$version"
