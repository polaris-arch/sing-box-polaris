#!/usr/bin/env bash
set -euo pipefail

branches=$(git branch -r --contains HEAD)
# The patched default branch follows the upstream testing release line.
branches=$(printf '%s\n' "$branches" | sed 's#origin/polaris-main$#origin/testing#')
if echo "$branches" | grep -q 'origin/stable'; then
  track=stable
elif echo "$branches" | grep -q 'origin/testing'; then
  track=testing
elif echo "$branches" | grep -q 'origin/oldstable'; then
  track=oldstable
else
  echo "ERROR: HEAD is not on any known release branch (stable/testing/oldstable)" >&2
  exit 1
fi

if [[ "$track" == "stable" ]]; then
  tag=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
  if [[ -n "$tag" && "$tag" == *"-"* ]]; then
    track=beta
  fi
fi

case "$track" in
  stable)    name=sing-box;           docker_tag=latest ;;
  beta)      name=sing-box-beta;      docker_tag=latest-beta ;;
  testing)   name=sing-box-testing;   docker_tag=latest-testing ;;
  oldstable) name=sing-box-oldstable; docker_tag=latest-oldstable ;;
esac

# Package identity retains the upstream track; only asset names use Polaris.
package_name="$name"
name="sing-box-polaris${name#sing-box}"

echo "track=${track} name=${name} docker_tag=${docker_tag}" >&2
echo "TRACK=${track}" >> "$GITHUB_ENV"
echo "NAME=${name}" >> "$GITHUB_ENV"
echo "PACKAGE_NAME=${package_name}" >> "$GITHUB_ENV"
echo "DOCKER_TAG=${docker_tag}" >> "$GITHUB_ENV"
