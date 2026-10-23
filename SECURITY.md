<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Report it through
[HackerOne](https://hackerone.com/nextcloud), as described in the
[Nextcloud security policy](https://nextcloud.com/security/). Reports go to
the Nextcloud security team.

## Supported versions

| App version | Nextcloud | Supported |
| --- | --- | --- |
| latest 1.x release | 36 | ✅ |
| older releases | | ❌ |

Fixes are released as a new version of the app on the app store. Update to
the latest release; older releases do not get fixes.

## Third-party components

What the app ships:

- **JavaScript:** the npm packages under `dependencies` in `package.json`,
  bundled into `js/`. Each release has a CycloneDX SBOM of them attached
  (`intrusion_detection-<version>.cdx.json`).
- **PHP:** none. `composer/` holds only Composer's autoloader for the app's
  own classes.

Everything else in `package.json` (`devDependencies`) and in `vendor-bin/`
only builds, tests or checks the app and is not part of the release.

### Update policy

- Dependabot proposes npm updates every week and GitHub Actions updates every
  month.
- CI runs `npm audit --omit=dev` on every pull request and on pushes to the
  main branches, so a known advisory in a shipped package fails the build.
- Time frames from the day an advisory for a shipped package is known:

  | Severity | Fixed release |
  | --- | --- |
  | Critical, High | within 7 days |
  | Moderate | within 30 days |
  | Low | with the next regular release |

- Advisories in packages that are only used to build or test the app are
  fixed with the regular Dependabot updates. They do not reach the release.

## Further reading

- [Browser security](docs/browser-security.md)
- [Resource limits](docs/limits.md)
- [Functionality that needs care](docs/dangerous-functionality.md)
