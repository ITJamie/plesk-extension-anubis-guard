# Anubis Guard for Plesk

A Plesk extension for enabling Anubis per website, with literal path-prefix and IPv4/IPv6 exclusions. Customers manage their authorized sites; administrators manage all sites.

This is an independent, unofficial extension. Its author has no affiliation with the Anubis project, Techaro, or Plesk. It is not developed, sponsored, endorsed, or supported by those projects or organizations. Anubis is developed and maintained by its upstream authors; issues with this extension should be reported to this repository.

Licensed under the [MIT License](LICENSE). Upstream components retain their own copyright and license notices; see [third-party notices](THIRD_PARTY_NOTICES.md).

Each site also has a **Challenge images** selector: keep **Anubis artwork** (the default) or choose **Generic status icons** for neutral checking, success, and rejection shields. This replaces the three visitor-facing image responses without modifying Anubis's runtime files. After saving, hard-refresh the challenge page or use a private window if the browser cached the previous artwork. The setting is available to administrators and authorized site managers; custom uploads and arbitrary image paths are not part of this option.

Administrators can configure shared **GeoIP Country and ASN databases** using MaxMind credentials or local file paths with `*` patterns. GeoIP defaults to disabled, removing database-dependent rule warnings without requiring credentials. See [GeoIP setup and recovery](docs/geoip.md).

Administrators can manage the server-wide **Anubis runtime**: refresh official stable GitHub releases, download verified versions, and explicitly activate a downloaded version. **Automatic** uses the version pinned in this extension's code; an **Override** survives extension upgrades. Downloading alone does not change running sites. See [runtime versions and recovery](docs/runtime-versions.md).

Choose **Protect → Only selected paths** to protect a section such as `/forums/*`. Enter one section per line in **Protected paths and subpaths**. `/forums`, `/forums/`, and `/forums/*` all cover `/forums` and its descendants (including `/forums/thread/123`), while `/`, `/about`, and `/forums-other` bypass Anubis. Matching is case-sensitive; only a trailing `/*` is supported. Choose **Entire site** to protect from `/`, which remains the default for existing sites.

Other URLs go directly to the site's private backend and remain independent of Anubis availability. Path and IP exclusions still bypass protection within selected sections; the site's challenge and failure settings apply to protected requests. Anubis's internal challenge routes remain connected, and certificate-renewal token routes remain independent. Protection follows the requested URL: if application rewrites or aliases expose the same content at another URL, include that URL too.

Each site has a challenge mode and a proof-of-work base difficulty (1–6, default 2):

- **Adaptive:** preserves the default suspicion thresholds. Low-risk traffic passes or receives a one-second refresh; higher suspicion uses proof-of-work difficulty at the base, base+2, and base+4, each capped at 6. The default remains 2/4/6.
- **Fixed proof of work:** requests reaching the fallback policy must complete JavaScript proof of work at the selected difficulty.
- **Lightweight browser refresh:** requests reaching the fallback policy receive a one-second refresh without JavaScript proof of work. The saved proof-of-work difficulty is retained for switching back.

Path/IP exclusions and built-in allow, deny, and explicit challenge rules take priority in every mode. Higher proof-of-work difficulty increases visitor CPU work sharply, so start at 2. Existing visitor tokens may remain valid after a change; use a private browser window to test new challenges. Upgrades preserve existing behavior until settings are saved. Customers use the same controls under the existing **Manage Anubis protection** plan permission.

**Development preview:** installer ZIP, source, and automated checks are available. Live Plesk installation, browser challenges, service lifecycle, and certificate renewal have not been validated in this managed workspace. Complete the [acceptance checks](docs/acceptance.md) before public release.

## Compatibility

- AlmaLinux 9, x86_64; Plesk Obsidian 18.0.81 or newer.
- Plesk nginx, either proxying to Apache or serving PHP-FPM directly.
- systemd, Python 3.9+, and Plesk's native PHP extension SDK.
- AlmaLinux's `libmaxminddb` package providing `/usr/bin/mmdblookup` for database validation (already installed on the supplied server).
- Direct client connections. Custom CDN/real-IP configurations and arbitrary nginx includes require compatibility review and are rejected rather than partly protected.
- SELinux enforcing is rejected until a local policy has been reviewed. The extension does not disable SELinux.

The initial implementation uses Plesk's native PHP controller/view SDK with bundled JavaScript and CSS. Building or installing the panel requires no Node packages, React runtime, CDN, or external JavaScript. This replaces the React frontend tooling in the initial proposal while retaining the Plesk SDK backend.

## Build

Anubis **1.28.1 linux-amd64** is pinned in `runtime.lock.json`, including its upstream SHA-256. By default the ZIP contains the extension and a verified installer, with no Anubis binary:

```sh
python3 tools/build.py
```

Output: `dist/anubis-guard-0.8.2.zip` and its SHA-256 file. On installation, the helper downloads that exact GitHub release over HTTPS, checks its SHA-256 before extracting or executing it, and caches an immutable version under `/var/lib/plesk-anubis/runtime/`. A failed download or checksum mismatch aborts before changing services or website routing. The cached runtime is reused; there are no request-time downloads or automatic tracking of `latest`.

For an offline installer, bundle the verified upstream release:

```sh
python3 tools/build.py --download-runtime
```

Or download the archive on another machine and build offline:

```sh
python3 tools/build.py --runtime-archive /path/to/anubis-1.28.1-linux-amd64.tar.gz
```

These options produce `dist/anubis-guard-0.8.2-offline.zip`, retaining the complete upstream runtime archive contents and integrity manifest. ZIP paths, timestamps, permissions, and ordering are deterministic.

This workspace cannot resolve external hosts from the shell, so the binary payload and live download could not be tested here. A reproducible, **non-installable source archive** is also available:

```sh
python3 tools/build.py --source-only
```

## Install and use

After building a release ZIP and completing the staging acceptance checks, install it through **Extensions → My Extensions → Upload Extension**, or as root:

```sh
plesk bin extension --install /path/to/anubis-guard-0.8.2.zip
```

Administrators open **Extensions → Anubis Guard**. Customers use **Anubis Guard** in the hosting panel navigation or the website's Security section. The domain button opens that website's controls; the navigation entry lists all sites the account is authorized to manage. New websites start disabled. Enable a site, optionally add exclusions, and save. Aliases inherit the hosting domain's configuration; independently hosted subdomains appear separately.

Customers can enable/disable protection, edit both path and IP exclusions, and inspect status/errors for their authorized websites. Each list and save uses Plesk's domain-access and permission checks. Administrators retain global access, including when customer management is restricted.

### Plan permission

The native Plesk permission **Manage Anubis protection** (`manage_protection` within this extension) is declared enabled by default. It can be restricted through service plan/subscription permissions. Both the subscription permission and the current client's permission must allow management; Plesk-authorized delegated sites use the same checks.

Revoking the permission hides customer entry points where applicable and prevents customer reads/changes for affected sites. It does **not** turn off existing protection or stop Anubis. An administrator can still inspect or disable those sites. Re-granting the permission restores customer controls.

To upgrade an existing installation:

```sh
plesk bin extension --upgrade /root/git/extension/dist/anubis-guard-0.8.2.zip
```

Refresh the panel after upgrading. Validate the customer/plan checks in `docs/acceptance.md` using separate customer accounts before broader rollout.

Excluded paths are literal decoded prefixes, not regular expressions. `/api/` covers descendants; `/api` also covers `/apiary`. Query strings, percent escapes, traversal, root-wide exclusions, and Anubis endpoint exclusions are rejected. Excluded IPs accept addresses or CIDRs; CIDRs are normalized. These requests bypass Anubis's policy checks, while ordinary requests use its pinned default policy.

Each site has an **If Anubis is unavailable** setting, available to administrators and authorized customers:

- **Fail closed** (default, including existing sites): Anubis connection failures return HTTP 503.
- **Fail open**: nginx tries the site's private backend when the Anubis connection fails or times out, serving the site without bot protection. Challenge pages, denials, and HTTP error responses never trigger this fallback. Protection is tried again after a short two-second failure backoff.

Failover is possible only before a response starts. Streaming uploads and requests already sent may not be retryable; non-idempotent requests are not deliberately replayed after being sent. The fail-open connect timeout is two seconds; the existing 3600-second proxy read timeout remains for long-running requests and WebSockets. Initial activation and settings changes still require a healthy Anubis process and roll back on failure. Save the selected mode while Anubis is healthy to apply it to subsequent outages.

Automatic Anubis recovery continues in both modes. ACME token requests remain available through a narrow private-origin route, including while Anubis is down.

## Checks and operations

```sh
tools/check.sh
```

See [architecture and interfaces](docs/architecture.md), [operations](docs/operations.md), and [release acceptance](docs/acceptance.md).

GitHub Actions runs checks on pushes and pull requests and builds downloadable ZIP artifacts. To publish a release, update the extension version and changelog, then push a matching `vMAJOR.MINOR.PATCH` tag. See [GitHub checks and releases](docs/releases.md) for the workflow and requirements.
