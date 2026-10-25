#!/usr/bin/env bash

set -euo pipefail

version="$(tr -d '[:space:]' < VERSION)"
tag="v${version}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([a-zA-Z0-9.-]+)?$ ]]; then
  echo "::error::Invalid VERSION: $version"
  exit 1
fi

set +e
git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null
lookup_status=$?
set -e

case "$lookup_status" in
  0)
    git fetch --no-tags origin "refs/tags/${tag}:refs/tags/${tag}"
    tag_commit="$(git rev-parse --verify "refs/tags/${tag}^{commit}")"

    if [[ "$tag_commit" == "$GITHUB_SHA" ]]; then
      should_release=true
      create_tag=false
      echo "Tag $tag already points to $GITHUB_SHA; reconciling release."
    else
      should_release=false
      create_tag=false
      echo "Tag $tag points to $tag_commit, not $GITHUB_SHA; skipping release."
    fi
    ;;
  2)
    should_release=true
    create_tag=true
    echo "Tag $tag does not exist; releasing."
    ;;
  *)
    echo "::error::Unable to inspect remote tag $tag (git ls-remote exited $lookup_status)."
    exit "$lookup_status"
    ;;
esac

{
  echo "should_release=${should_release}"
  echo "create_tag=${create_tag}"
  echo "version=${version}"
  echo "tag=${tag}"
} >> "$GITHUB_OUTPUT"
