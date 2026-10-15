# Release acceptance

## Generic challenge images (0.7.0)

As an administrator and as an authorized customer, choose **Challenge images → Generic status icons** for a test domain and save. Use a fresh private browser session and confirm checking, success, and denial display neutral clock/check/cross shield icons. Fetch each of the three exact image URLs with the normal Anubis query string; confirm WebP content type and no-store caching. Verify normal challenge JavaScript and verification callbacks still work, and that neighbouring paths, arbitrary files, and non-GET/HEAD image requests are not exposed through the alias.

Repeat for HTTP/HTTPS, Apache/PHP-FPM, selected paths, and fail-open/fail-closed. Confirm image choices remain isolated between domains, survive reload, and are restored by a failed configuration change. Switch back to Anubis artwork and hard-refresh; legacy configurations must still default to original artwork. Check nginx worker read access to the installed copies, including after reboot/upgrade. Live HTTP/browser verification remains pending in this managed workspace.

## GeoIP management (0.6.0)

Upgrade an existing protected site and confirm default Disabled removes GeoIP/ASN warnings without changing ordinary challenge behavior. Confirm customers cannot see the global form or reach any GeoIP API, including through direct requests.

As administrator, configure valid MaxMind credentials and watch the queued job complete. Confirm Country and ASN build dates and resolved sources are displayed, no key is returned by status or logged, and both databases load in each active Anubis instance without warnings. Test invalid credentials, a failed download, and a source switch failure; existing services and active snapshots must remain usable. Confirm nginx is not restarted or reconfigured during GeoIP jobs.

For local mode, supply exact paths and patterns with dated directory/filename components. Touch an older database and confirm the newer database build date still wins. Test ties, corrupt matches, absent matches and wrong database types. Replace sources atomically and confirm a new valid pair is detected within five minutes. Removing sources must retain working snapshots. An unchanged pair must not restart Anubis. Verify scheduled MaxMind checks occur once per day and manual refresh remains available.

Interrupt activation and verify reconcile restores the prior pair/policies/credentials. A rollback failure must retain its journal and block new saves until recovery. Check fail-open/fail-closed behavior during sequential Anubis restarts, and verify suspended sites are not started. Clear credentials explicitly and confirm removal; successful uninstall must remove credentials and the timer/worker. Live download credentials, service restarts and browser checks remain operator acceptance tests outside this workspace.

## Selected-path protection (0.5.0)

On a staging site, select **Only selected paths**, enter `/forums/*`, enable fixed proof of work, and save. With fresh cookies verify that `/forums`, `/forums/`, and a nested forum URL receive the normal challenge (subject to built-in allow rules), and the challenge assets/callback work. `/`, `/about`, and `/forums-other` must reach the original site without a challenge. Verify case-sensitive matching and encoded/normalized URLs against the application's own routes. Add an excluded path under `/forums` and an IP exclusion and confirm they still bypass challenges. Add another included section and verify both; switch to Entire site and verify normal domain-wide protection returns.

Stop Anubis briefly with fail closed selected: unselected URLs must still work while selected URLs return HTTP 503. Repeat with fail open and verify selected URLs use the fallback. Restart the service after each test. Confirm ACME token requests remain independent. Repeat with HTTP/HTTPS, Apache/PHP-FPM, and customer access. Check save/reload persistence and rollback on a failed update. Avoid exposing protected content through unselected application aliases/internal rewrites. Live HTTP/socket behavior remains a staging check outside this workspace.

## Save connection continuity (0.4.1)

Access the panel through its port 443 nginx proxy. Save settings for an enabled site and confirm the POST receives JSON success, with nginx retaining its master process and no stop/start events in the journal. Repeat activation, deactivation, and a failed update/rollback. For Apache hosting, verify origin guards still take effect and its journal records a graceful reload. For nginx-only hosting, verify inactive/absent Apache is not started. Interrupt the browser connection during a save and confirm the UI explains that settings may already have been applied, offers Refresh status, and never repeats the POST automatically. Live service reloads cannot be exercised in this workspace.

## Current evidence

The implementation was checked on the supplied AlmaLinux 9.8/Plesk 18.0.81.3 environment using standalone PHP 8.4, Python 3.9, and nginx 1.30.5.

- Pure Python tests cover settings, policy generation, nginx transformation, origin guards, transaction ordering, rollback, interrupted-apply recovery, and deterministic packaging.
- PHP boundary tests cover customer/administrator access, cross-customer isolation, plan/client permission revocation, extension-context restoration, CSRF, mutation methods, identifiers, rendered-template handling, and early-return source templates.
- Real nginx parses generated Apache-proxy and PHP-FPM configurations successfully. The sandbox then rejects socket operations during `nginx -t`; a full nginx configuration test and service startup remain unverified.
- PHP and JavaScript syntax checks pass.
- The pinned Anubis archive could not be fetched because shell DNS/network access is restricted. The default installer ZIP contains a pinned, hash-verifying download routine; no runtime binary is included. Payload tests cover failed downloads/checksums, archive safety, offline bundles, and cached-version reuse using synthetic fixtures.

The operator has confirmed that version 0.1.3 activates successfully on this server. The new 0.2.0 customer/plan flows are covered by SDK-boundary fixtures and browser-script tests; interactive validation with real Plesk customer accounts remains pending.

## Required staging matrix

Use disposable domains on an unrestricted AlmaLinux 9/Plesk installation. Remove the domains after testing. Record exact Plesk, nginx, Apache, PHP, and extension versions and the release ZIP checksum.

| Scenario | Acceptance |
| --- | --- |
| Install with no sites | Extension opens for admin, empty state is useful, no website routing changes |
| Customer controls | Customer can enable, disable, edit both exclusions, and view status/errors for its own sites |
| Customer isolation | Two customers cannot list, open, or mutate each other's sites; forged domain IDs receive 403 |
| Delegated/restricted accounts | Plesk-authorized delegated domains are available; denied client permissions prevent reads and writes |
| Plan permission | Native permission appears, defaults enabled, and follows subscription synchronization/overrides |
| Permission revocation | Customer controls disappear and stale-page saves fail; existing protection continues and admin access remains |
| Permission re-grant | Customer controls return with prior protection/exclusion settings intact |
| Customer navigation | Hosting navigation opens authorized sites; a domain Security button focuses that site; aliases use the hosting domain |
| Runtime acquisition | Pinned release downloads once; checksum/download failures leave site routing untouched; a second install reuses the verified cache; offline bundles install without network access |
| Apache proxy and nginx-only/PHP-FPM | HTML, static files, PHP, nginx caches, and application routes go through Anubis |
| Browser challenge | Real browsers complete proof of work, return to the original URI/query, and retain valid cookies across restart |
| Default policy and exclusions | Default bot policy applies; literal path prefixes and IPv4/IPv6/CIDR exceptions work only as configured |
| HTTPS, HTTP, redirects | Original scheme, host, IP, PHP HTTPS state, redirects, and non-default ports remain correct |
| IPv4/IPv6, default IP domain, aliases, subdomains | No route collisions or alternative public routes bypass protection |
| Spoofing | Forged forwarding/origin/route headers and client Connection header lists do not bypass policy |
| Direct Apache backend | Requests to backend ports without the internal origin key are rejected |
| ACME | New issuance and renewal work; only syntactically valid ACME tokens use the outage bypass |
| Uploads, streaming, WebSockets | Original application behavior remains intact through all proxy layers |
| Failure | Default fail closed returns 503 when Anubis is unavailable; fail open serves the private site backend; recovery restores protection |
| Invalid configuration | Last working policy/routing returns; error is visible; no success is reported |
| Concurrency and interruption | Concurrent saves serialize; killing an apply leaves a recoverable journal |
| Rename, suspension, hosting conversion, deletion | Settings stay with ID, unsupported hosting remains blocked, stale instances/data are cleaned |
| Reboot | Socket directories exist before nginx starts; enabled instances recover and protection remains enforced |
| Plesk regenerate/repair | Protection and origin guard survive configuration regeneration |
| Upgrade and uninstall | Settings survive upgrade; uninstall restores original routing before hook removal |
| Existing extensions | Test SSL It!/Let's Encrypt, WAF, Node.js, and WordPress Toolkit as applicable; document rejected custom includes |

## Public release gate

Build the installer ZIP, complete this matrix (including a real runtime download), and record results here before publishing. Add the project's chosen license, publisher identity, repository/support URLs, and release destination before public distribution. Plesk Catalog submission is a later task.
## Challenge settings (0.3.0)

On a test domain, verify that a legacy configuration displays Adaptive and difficulty 2. Save fixed proof of work at difficulty 2, then 3, and open a fresh private browser session for each test. Confirm the selected settings survive a panel refresh and the generated `policy.json` uses the selected `fast` difficulty. Test lightweight browser refresh with JavaScript disabled; verify its fallback uses `metarefresh` with difficulty 1. Switch back to Adaptive and verify the displayed effective levels match the generated policy. Confirm an excluded path/IP still bypasses the challenge and built-in bot allow/deny behavior remains intact. Repeat the save as the site's customer and verify another customer's site remains inaccessible.

For a failed challenge update, verify the prior policy/settings are restored and the existing service recovers. Reject out-of-range or non-integer difficulty through the API without changing state. Existing visitor cookies may bypass new challenges, so always test with fresh cookies.

## Failure behavior (0.4.0)

Use a staging domain and its numeric Plesk domain ID. Save fail closed, stop `plesk-anubis@ID.service`, and confirm an uncached ordinary request returns HTTP 503. Restore the service, save fail open, stop the service again, and confirm the same request reaches the site without a challenge. The reconcile timer may restart the service during testing; keep the outage brief and check the service journal. Restart the service after each test and confirm challenges return (allow for the two-second nginx backoff). Repeat for HTTP/HTTPS and Apache/PHP-FPM, checking the original scheme, client IP, redirects, request method/body, and domain isolation. ACME must continue to work in either mode.

With Anubis running and fail open selected, verify challenge pages and built-in bot denials still appear. Confirm application 4xx/5xx responses do not trigger a second request to the backend. Test a POST while Anubis cannot connect and verify it reaches the backend once; verify a request interrupted after transmission is not deliberately replayed. Streaming responses cannot fail over after headers/body have been sent. Repeat save/status as a customer, verify reload preserves the choice, and confirm legacy sites default to closed. A failed update must restore the previous mode and routing. Live socket/HTTP failover cannot be exercised in the managed workspace.

