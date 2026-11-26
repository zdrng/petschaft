#!/usr/bin/env bash
# petschaft git signing demo.
#
# Each run appends one line to demo.txt in a separate test repository and creates a
# commit signed by the Trezor. The commit message is typed by you and shown on the
# Trezor before you confirm. Afterwards OpenSSH's own ssh-keygen verifies the signature.
#
# Only the test repository's local git config is changed; your global git config and
# ~/.ssh stay untouched.
#
#   PETS_DEMO_REPO   test repository   (default: ~/petschaft-git-demo)
#   PETS_GIT_PUBKEY  key line from `pets pubkey git` (default: ~/.config/petschaft/git.pub)
#   PETS_BIN         pets binary       (default: build with `nix build .#petschaft`)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd -P)
repo=${PETS_DEMO_REPO:-$HOME/petschaft-git-demo}
mkdir -p "$(dirname "$repo")"
repo="$(cd "$(dirname "$repo")" && pwd -P)/$(basename "$repo")"
pubkey_file=${PETS_GIT_PUBKEY:-$HOME/.config/petschaft/git.pub}

pets=${PETS_BIN:-}
if [[ -z $pets ]]; then
  echo "building petschaft ..."
  nix build "$root#petschaft" -o "$root/result" --quiet
  # Store path, not the result symlink: stable until the next rebuild.
  pets=$(realpath "$root/result/bin/pets")
else
  pets=$(realpath "$pets")
fi

if [[ ! -f $pubkey_file ]]; then
  echo "missing $pubkey_file"
  echo "create it with:  $pets pubkey git > $pubkey_file"
  exit 1
fi
key=$(head -n 1 "$pubkey_file")
# algorithm, base64 key, optional comment (any text: pets finds the identity by the
# key's fingerprint, never by the comment)
if [[ ! $key =~ ^(ssh-ed25519|ecdsa-sha2-nistp256)\ ([A-Za-z0-9+/]+={0,2})(\ .*)?$ ]]; then
  echo "$pubkey_file does not contain a line printed by 'pets pubkey <name>'"
  exit 1
fi
key_no_comment="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"

# Never touch a real repository: only a fresh directory or one this script created.
if [[ ! -e $repo ]]; then
  git init -q -b main "$repo"
  git -C "$repo" config petschaft.demo true
  echo "# petschaft git signing demo" > "$repo/demo.txt"
  echo "created test repository $repo"
elif [[ $(git -C "$repo" config --get petschaft.demo 2>/dev/null) != true ]]; then
  echo "$repo exists and is not a petschaft demo repository; choose another PETS_DEMO_REPO"
  exit 1
fi
cd "$repo"

# Repo-local settings only.
email="petschaft-demo@localhost"
git config user.name "petschaft demo"
git config user.email "$email"
git config gpg.format ssh
git config gpg.ssh.program "$pets"
git config user.signingkey "key::$key"
git config commit.gpgsign true
# Who may sign (for verification): this key, for the demo e-mail, git namespace only.
printf '%s namespaces="git" %s\n' "$email" "$key_no_comment" > .git/allowed_signers
git config gpg.ssh.allowedSignersFile "$repo/.git/allowed_signers"

read -r -p "Commit message: " msg || true
if [[ -z $msg ]]; then
  echo "empty message, nothing committed"
  exit 1
fi

printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >> demo.txt
git add demo.txt
git commit -q -S -m "$msg" --only demo.txt

echo
git log --show-signature -1
echo
if git verify-commit HEAD 2>/dev/null; then
  echo "OK: signature verified by ssh-keygen ($(git rev-parse --short HEAD))"
else
  echo "FAILED: signature did not verify"
  exit 1
fi
