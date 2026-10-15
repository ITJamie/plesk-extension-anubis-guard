# Architecture and interfaces

## Request flow

```text
Public Plesk nginx (TLS, redirects, ACME)
    → /run/plesk-anubis/ID/anubis.sock
    → Anubis, with persistent per-domain challenges
    → private nginx ingress socket
    → validated domain-local route socket
    → original Plesk nginx content routing
    → Apache or PHP-FPM, as originally configured
```

Anubis has one process per enabled Plesk domain ID. Private routes retain the original IP/vhost and HTTP/HTTPS context. Certificates stay with Plesk. Static content, nginx caches, PHP handling, extension routes, and Apache proxying run behind the filter. Existing SEO redirects and suspended-site responses retain their normal behavior.

The site's `protection_scope` is `all` (legacy default) or `selected`, with `included_paths` containing up to 100 normalized sections. For selected scope, an exact nginx location for each section root and a `^~` prefix location for its descendants use the normal Anubis/failover proxy. The default `/` location goes directly to the corresponding private content socket with regenerated forwarding headers; origin-key insertion still occurs only inside the private backend. This avoids dependence on Anubis for other URLs, including fail-closed outages. `/.within.website` and descendants are always routed through Anubis so challenge assets and callbacks work. ACME retains its narrow bypass location. Included paths reject query strings, traversal, unsafe nginx literals, and arbitrary wildcards; a terminal `/*` or slash is normalized away. Exclusions remain Anubis ALLOW rules applied inside protected sections. These settings affect nginx routing rather than the Anubis policy, so there is no catch-all Anubis rule that could challenge an unselected URL. Application rewrites may expose identical content at different URLs; operators must include each public URL that requires protection.

`pm_Hook_WebServer::processTemplate` targets only `domain/nginxDomainVirtualHost.php`. PHP template source is wrapped in an output buffer with `try/finally`, including early returns. Already rendered configuration is also supported. A lexer and structured parser split complete server blocks; configuration is not modified with a global text replacement. Vendor templates are never edited.

Known FastCGI includes are expanded, preserving original scheme/HTTPS/port values. Unknown includes and custom real-IP directives fail with an actionable compatibility error. This deliberate restriction also applies to third-party extensions adding unreviewed includes. Plesk template changes must pass compatibility tests before a broader release claim.

The public edge overwrites forwarding headers and the private route identifier. Connection headers are regenerated for upgrades, rather than accepting client-supplied hop-by-hop header lists. Private sockets require access to a root-controlled directory. The Apache SDK hook rejects requests without a persistent random origin key. The key is inserted only when proxying to the Plesk-supplied Apache origin, cleared at the public edge, and removed in Apache before application handling. An internal environment flag preserves validation across Apache rewrites; the key is not exposed to PHP or unrelated upstreams.

## Panel API

The per-site `image_style` setting accepts only `original` (legacy default) or `generic`. For generic mode, the public edge adds exact nginx locations for `/.within.website/x/cmd/anubis/static/img/{happy,pensive,reject}.webp`. Each location aliases a fixed extension-owned file under `/var/lib/plesk-anubis/assets/generic-v1/`, permits GET/HEAD, returns `image/webp`, and sends `Cache-Control: no-store` plus `X-Content-Type-Options: nosniff`. There is no directory alias, variable filesystem path, user upload, HTML substitution, or Anubis overlay environment variable. Challenge APIs/scripts retain their existing routing. Images are installed/repaired with root ownership, nginx group read access, 0750 directories, and 0640 files. This works in both protection scopes and failure modes. Runtime preparation publishes missing/damaged assets before a generic setting can become active; routing changes and rollback follow the existing site transaction.

Both endpoints require an authenticated Plesk session. Administrators have global access. Other accounts must have Plesk domain access plus the subscription and client `manage_protection` permissions. Responses are JSON and are not cacheable.

| Endpoint | Input | Result |
| --- | --- | --- |
| `GET index.php/api/list` | None | Authorized `domains` with ID, name, hosting state, enabled flag, exclusions, health, and last error; runtime version and `is_admin` |
| `POST index.php/api/save` | `id`, boolean `enabled`, string arrays `paths` and `ips`; session-bound `X-Anubis-CSRF` header | `{ "ok": true }` or an error |
| `GET index.php/api/geoipstatus` | Administrator session | Active source/database metadata, saved-key boolean, job status and recovery flag; no secrets |
| `POST index.php/api/geoipsave` | Administrator, CSRF, source settings | HTTP 202 and queued job ID; key input is never returned |
| `POST index.php/api/geoiprefresh` | Administrator and CSRF | HTTP 202 and queued job ID for the active source |

GeoIP uses its own nonblocking worker lock to serialize jobs and the shared runtime apply lock during activation/recovery. Downloads and validation run outside the apply lock. Source configuration, private credentials, latest job, and pending activation journal live under the root-controlled `geoip` directory. Immutable content-addressed generations hold a shared Country/ASN pair. Policies reference fixed generation paths; enabled GeoIP preserves all flattened pinned rules, while disabled mode omits whole dependent rules to preserve the prior effective behavior without warnings. See [GeoIP operations](geoip.md) for scheduling and failure behavior.

Missing/invalid CSRF returns 403; mutation by GET returns 405. Unauthorized and unknown domain IDs return the same 403 to customers before the mutation helper is invoked. Domain IDs and settings are revalidated in the privileged helper. The API accepts no upstream URL, executable, arbitrary file path, or policy expression. The UI creates text nodes for domain names and errors.

The fixed `pm_ApiCli::callSbin` helper supports `status`, `status-scoped`, `save ID`, `render ID TEMPLATE`, `preflight`, `install`, `reconcile`, and `uninstall`. JSON settings and rendered templates go over stdin. Commands execute as argument arrays with fixed executable paths, never via a shell.

For customers the API enumerates allowed Plesk domain IDs, sends only that scope to `status-scoped`, then filters and rechecks the returned rows. The helper does not probe health or return settings outside that scope. An empty scope never falls back to all sites. The legacy root CLI `status` remains unscoped and does not read stdin. Requested mutation IDs are checked against live Plesk access and both permission gates before `save` is invoked.

Hosting navigation and domain Security buttons use the same access helper. Domain context (`site_id`) is checked on entry and focuses the browser view; it never grants access by itself. Custom permission checks bind to this extension's module context and restore the host context afterward, including errors in visibility callbacks.

The permission controls customer management access, not running services. No background job or web-server hook disables protection when a plan permission changes. This preserves active protection and administrator recovery access when customer control is revoked.

## State and transactions

Root-owned state is under `/var/lib/plesk-anubis`. Settings use domain IDs and persist across renames. Signing keys are separate from panel-visible settings. Each domain has an independent bbolt challenge database and a distinct host-only cookie name.

Apply operations hold a file lock and write a durable recovery journal before changing routing. A new Anubis policy must start and answer its private health endpoint before Plesk regenerates configuration. `httpdmng --reconfigure-domain DOMAIN -no-restart` performs Plesk's regeneration without hard-restarting the panel's nginx proxy. nginx and active Apache configuration are validated, then active Apache is gracefully reloaded before nginx. Apache is skipped when absent or inactive. Disabling stops Anubis only after normal routing is restored. Failure restores the previous settings, service configuration, and routing. Failed rollback retains the journal and blocks further saves until reconciliation succeeds. Browser connection failures never trigger automatic save retries; the user is prompted to inspect current status because a disconnected request can still complete server-side.

The systemd timer reconciles every minute and after boot. It recovers interrupted operations, restarts unhealthy instances, stops suspended/non-web-hosted instances, and removes deleted-domain runtime data. `systemd-tmpfiles` recreates enabled-domain socket directories before nginx starts. Fail-closed domains remain unavailable during a service outage. Fail-open domains use nginx upstream groups per original vhost, with Anubis as primary and that vhost's private content socket as backup. Forwarding headers are overwritten at the edge for either endpoint, and the backend continues to inject the Apache origin key only for trusted origins.

`failure_mode` is strictly `closed` or `open` and defaults to `closed` for legacy settings/state. It is included in status and saved under the same authorization/transaction checks as other site settings. It affects nginx generation, not Anubis policy. Fail-open locations use `proxy_next_upstream error timeout`, two tries, a two-second connect timeout, and no HTTP-response interception. The primary is temporarily skipped for two seconds after a failure; the backup remains a private Unix socket. This preserves challenges, denials, and application HTTP errors. Request buffering remains off, and `non_idempotent` retries are not enabled, so failover is limited to requests nginx can safely retry before a response starts. The existing 3600-second read timeout is retained for long-lived traffic. Initial activation/settings updates still require Anubis health, regardless of failure mode.

No background telemetry or public metrics endpoint is added. Service output goes to the system journal. Runtime policy imports use Anubis's embedded, version-pinned defaults.

Runtime downloads happen only during installation or an explicit extension update. HTTPS, a pinned archive hash, bounded downloads/extraction, and immutable cached versions keep transient GitHub failures separate from live request handling. An optional offline ZIP bundles the same verified release. No mutable `latest` tag or unattended runtime upgrade is used.
