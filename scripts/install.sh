#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination="${HOME}/.local/bin"
mkdir -p "$destination"
install -m 755 "$script_dir/DuckGuard" "$destination/DuckGuard"
printf 'Installed: %s/DuckGuard\n' "$destination"
case ":${PATH}:" in
  *":$destination:"*) ;;
  *) printf 'Add this to your shell configuration, then open a new terminal:\nexport PATH="$HOME/.local/bin:$PATH"\n' ;;
esac
printf 'Run: DuckGuard --help\n'

