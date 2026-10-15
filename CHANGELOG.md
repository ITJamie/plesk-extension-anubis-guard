# Changelog

## 0.8.2

ci fixes

## 0.8.1 — keep website pages focused

- Add GitHub Actions checks, downloadable ZIP artifacts, and tested tag-driven GitHub releases with changelog notes and checksums. Read package versions directly from extension metadata.

- Show server-wide runtime and GeoIP controls only on the administrator's main extension page. Website-specific pages retain site controls for administrators and authorized customers.
- Verify actual template rendering for administrator/customer and main/site entry points.

## 0.8.0 — administrator runtime versions

- Add administrator-only official stable release discovery, verified downloads, explicit activation, Automatic/Override selection, and previous-version rollback. Preserve overrides across extension upgrades; Automatic follows the packaged pin.
- Run background jobs with status polling, cached release pages/ETags, offline reuse, and strict platform, tag, URL, digest, archive, and manifest validation.
- Probe candidate binaries without privileges against every active site policy before changing production. Restart sites sequentially, retain durable rollback journals, and recover interrupted switches without regenerating nginx.
- Keep binary, generated policy, and challenge database paired per version; preserve legacy and previous databases for recovery. Keep extension-managed bot rules unchanged when switching binaries.
- Cover access control, asynchronous browser behavior, integrity failures, failed probes, rollback/recovery, upgrade selection, and packaging.

## 0.7.0 — generic challenge images

- Add a per-site **Challenge images** choice for administrators and authorized customers: original Anubis artwork (default) or neutral generic status icons.
- Include original 384×384 WebP checking, success, and rejection shield icons, with SVG sources. Publish root-owned copies readable by nginx outside the website document roots.
- Replace only the three exact public image URLs with static nginx aliases. Keep challenge HTML, scripts, APIs, and upstream runtime files unchanged; generic responses use WebP content type and no-store caching.
- Persist and roll back the choice with existing site configuration, preserve legacy artwork by default, and support whole-site/selected-path protection in both failure modes.
- Validate fixed choices and test asset permissions/repair, exact routing, policy-update rollback, nginx syntax, packaging, and browser controls.

## 0.6.0 — shared GeoIP country and ASN databases

- Add administrator-only Disabled, MaxMind download, and Local file sources. Require MaxMind account ID plus license key or separate absolute Country/ASN file patterns.
- Resolve `*` in filenames or directory components using valid MMDB build dates, with filename tie-breaking. Check local sources every five minutes and MaxMind daily; provide manual refresh and asynchronous status.
- Store credentials root-only, redact status, strip authorization on cross-host HTTPS redirects, and bound downloads/archive extraction. Use AlmaLinux's existing `mmdblookup` native reader rather than adding the planned Python reader dependency.
- Publish immutable shared database pairs, restart active Anubis services sequentially only on changed contents, and retain the previous generation. Preserve working snapshots on refresh failure and recover activation through a durable journal.
- Flatten pinned upstream rules with recorded source hashes; when GeoIP is disabled, omit entire database-dependent rules to remove warnings while preserving other defaults.
- Disable GeoIP by default on upgrade, retain existing site settings, and add coverage for permissions, wildcard selection, real MMDB validation, download failures, scheduling, secrets, rollback, and browser job handling.

## 0.5.0 — protect selected paths

- Add an entire-site (default) or selected-path protection scope per site for administrators and authorized customers.
- Accept up to 100 protected sections; `/forums`, `/forums/`, and `/forums/*` normalize to the same section and cover the section root and its descendants without matching `/forums-other`.
- Route other URLs directly to the original private backend so they bypass Anubis even during fail-closed outages. Keep Anubis challenge endpoints routed to Anubis and ACME token routes independent.
- Retain path/IP exclusions inside protected sections, challenge settings, failure behavior, and the existing origin/header safeguards.
- Validate path syntax and reserved endpoints, persist and roll back scope transactionally, and preserve existing whole-site behavior for legacy state.
- Cover selected-path routing, validation, persistence/rollback, browser controls, and real nginx parsing for both failure modes and hosting variants.

## 0.4.1 — preserve panel connections during saves

- Generate Plesk vhosts with `-no-restart`, validate nginx and active Apache configuration, then gracefully reload Apache and nginx. This prevents saves from hard-restarting the nginx proxy used to access Plesk on port 443.
- Gracefully reload Apache before nginx so origin guards are applied; skip Apache when absent or inactive.
- Replace browser fetch/response connection errors with an actionable message explaining that settings may already have been applied. Never automatically replay an interrupted save.
- Add regression coverage for command ordering, validation failures, nginx-only installations, and interrupted browser requests.

## 0.4.0 — per-site failure behavior

- Add a customer/admin choice of fail closed (default, HTTP 503) or fail open (private backend fallback) for each site.
- Use nginx primary/backup upstreams per original vhost for fail open, preserving HTTP/HTTPS context, client headers, and Apache origin guards.
- Retry connection errors/timeouts only, with a two-second connect timeout and two-attempt limit. HTTP responses, including bot denials and application errors, do not trigger bypass. Preserve streaming and nginx's safeguards against replaying non-idempotent requests.
- Default existing configurations to fail closed, persist the setting transactionally, and show the selected outage behavior in the panel.
- Add validation, default/legacy, per-vhost routing, persistence/rollback, frontend, and real nginx parser coverage.

## 0.3.0 — per-site challenge controls

- Add adaptive, fixed JavaScript proof-of-work, and lightweight browser-refresh modes for administrators and authorized customers.
- Validate proof-of-work base difficulty as an integer from 1–6. Adaptive mode uses the base, base+2, and base+4 (capped at 6); defaults preserve the existing 2/4/6 thresholds.
- Preserve path/IP exclusions and embedded bot rules ahead of the selected fallback challenge. Refresh mode uses a one-second refresh.
- Return and persist challenge settings per domain, default older configurations safely, and restore the previous settings when an update fails.
- Version the browser asset and cover validation, policy generation, persistence, rollback, and panel save behavior.

## 0.2.1 — extension icons

- Add an original shield-and-jackal icon to the hosting navigation and domain Security entry.
- Include transparent PNG icons in the sizes required by the Plesk Extensions screen.

## 0.2.0 — customer controls and plan permissions

- Customers and Plesk-authorized delegated accounts can manage protection and all path/IP exclusions for their authorized sites.
- Add server-side domain and permission checks for reads, focused pages, and saves; privileged status requests are scoped to authorized IDs.
- Add hosting navigation and domain Security entry points, including single-domain focus.
- Register the native **Manage Anubis protection** plan/subscription permission, enabled by default. Revocation removes customer access while preserving running protection and administrator recovery access.
- Add cross-customer, permission, module-context, scoped-helper, and customer-interface regression coverage.

## 0.1.3 — service startup permissions and failure handling

- Explicitly apply runtime/configuration directory permissions after creation, including existing directories, so restrictive Plesk umasks cannot prevent Anubis from binding sockets.
- Bound health polling by a deadline, detect crashed services early, and include the exact journal command in startup errors.
- Avoid Plesk web-server regeneration when activation fails before routing changes; persist the routing phase for safe crash recovery.

## 0.1.2 — Plesk save-request compatibility

- Send Plesk's native forgery-protection token and AJAX header on panel requests, preserving the extension's separate CSRF check.
- Read the panel token on each request and block saves with a readable message when it is missing.
- Handle HTML panel error responses without attempting to display raw HTML or JSON parser errors.
- Add browser-script regression checks and version the panel asset URL to avoid stale JavaScript after upgrade.

## 0.1.1 — session compatibility fix

- Reuse Plesk's active native PHP session for CSRF tokens instead of starting Zend session namespaces.
- Fix the error when opening the extension and the same failure on settings saves.
- Add regression checks with an already active native session and fail-closed behavior when no session is available.

## 0.1.0 — development preview

- Administrator-only per-domain protection and path/IP exclusions.
- Native Plesk SDK panel with bundled JavaScript/CSS.
- Full-site Anubis routing for nginx-to-Apache and nginx-only/PHP-FPM.
- Private sockets, direct-Apache origin guard, and explicit fail-closed behavior.
- Persistent per-domain challenges, systemd recovery, transactional apply/rollback, and uninstall restoration.
- Pinned, hash-verified runtime download during installation, immutable version caching, optional offline bundles, and reproducible ZIP builds.

Live Plesk/runtime acceptance remains pending; see `docs/acceptance.md`.
