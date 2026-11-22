"""Require a release version increase for changes to package inputs."""

import subprocess
import sys

from semver import Version


MANIFEST = "VERSION"
PACKAGE_INPUTS = (
    "*.go",
    "firewall",
    "internal",
    "VERSION",
    "go.mod",
    "go.sum",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "vendor",
    ":(exclude)*_test.go",
    ":(exclude)customer",
    ":(exclude)internal/releaseplan",
    ":(exclude).github",
)


def version_at(revision):
    manifest = subprocess.check_output(
        ["git", "show", f"{revision}:{MANIFEST}"], text=True
    )
    value = manifest.strip()
    return Version.parse(value)


def main(base, candidate):
    diff = subprocess.run(
        ["git", "diff", "--quiet", "--no-renames", base, candidate, "--", *PACKAGE_INPUTS]
    )
    if diff.returncode == 0:
        print("Package inputs are unchanged.")
        return
    if diff.returncode != 1:
        diff.check_returncode()
    if version_at(candidate) <= version_at(base):
        raise SystemExit(f"Package inputs changed. Increase the version in {MANIFEST} in this PR.")
    print("Package version increased.")


if __name__ == "__main__":
    main(*sys.argv[1:])
