# Security

Report vulnerabilities through GitHub private vulnerability reporting:

https://github.com/Silmaril-Security/sdk-go/security/advisories/new

Private vulnerability reporting is enabled for this repository. Do not open a
public issue or pull request for a suspected vulnerability until the maintainers
have coordinated disclosure.

## Supported Versions

Security fixes target the latest tagged minor release. As of this repository's
current `VERSION`, that is the `0.4.x` release line. Older release lines may
receive fixes at maintainer discretion when users cannot upgrade promptly.

## Reporting Guidance

Do not include customer prompts, API keys, endpoint credentials, or production
payloads in GitHub issues, examples, tests, or pull requests.

When reporting privately, include:

- The affected SDK version and Go version.
- A minimal reproduction using synthetic data.
- Whether the issue affects request signing, metadata handling, transport
  behavior, blocking semantics, or sensitive-data exposure.
- Any known mitigation or upgrade path.

The maintainers will coordinate privately through the GitHub advisory thread
and publish an advisory or release notes when disclosure is appropriate.
