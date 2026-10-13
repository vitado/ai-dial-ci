#!/usr/bin/env bash
# Pull the previous CVE index (the artifact tagged 1), or find out that there is none.
#
# "None" is told by the Packages API and not by what the registry says to a pull:
# the package does not exist yet only when the API says 404 for it. Any other answer
# (no access, rate limit, a server error), and a failing pull of a package that is
# there, fails the step: a registry failure must not be taken for "there is none" and
# throw the history away.
#
# Environment: REPOSITORY (owner/name), IMAGE (ghcr.io/<owner>/<package>), DEST (the
# directory to pull into), BOOTSTRAP ("true": do not look, the build starts from the
# whole CVE list), GH_TOKEN (for gh), GITHUB_OUTPUT. Output: dir=<DEST> if pulled.
set -euo pipefail

if [[ "${BOOTSTRAP:-false}" == "true" ]]; then
  echo "::notice::Bootstrap: the previous index is not used"
  exit 0
fi

owner=${REPOSITORY%%/*}
package=${IMAGE##*/}
owner_type=$(gh api "repos/$REPOSITORY" --jq '.owner.type')
case "$owner_type" in
  Organization) scope=orgs ;;
  User) scope=users ;;
  *)
    echo "::error::Unknown owner type of $REPOSITORY: $owner_type"
    exit 1
    ;;
esac

response=$(gh api -i "$scope/$owner/packages/container/$package" 2>&1 || true)
status=$(awk '/^HTTP\//{print $2; exit}' <<< "$response")
case "$status" in
  200) ;;
  404)
    echo "::notice::No previous index ($package does not exist): the build starts from the whole CVE list"
    exit 0
    ;;
  *)
    echo "::error::Cannot tell whether $package exists (HTTP ${status:-none}): ${response%%$'\n'*}"
    exit 1
    ;;
esac

if ! oras pull "$IMAGE:1" --output "$DEST"; then
  echo "::error::Cannot pull $IMAGE:1. To start over, run this workflow by hand with 'bootstrap'"
  exit 1
fi
echo "dir=$DEST" >> "$GITHUB_OUTPUT"
