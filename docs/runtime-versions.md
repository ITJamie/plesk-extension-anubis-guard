# Runtime versions

Only Plesk administrators can see or call the runtime management controls. This is one server-wide binary selection for every protected site. Customer site controls and plan permissions do not grant access to it.

## Choose a version

Open Anubis Guard as administrator and find **Anubis runtime**.

1. **Refresh releases** retrieves ten official published releases per page and lists eligible stable releases from `TecharoHQ/anubis` on GitHub. Use **Load older releases** for more pages. Only Linux amd64 archives with GitHub SHA-256 asset digests are eligible; older releases without digests and prereleases are omitted.
2. Select a release and **Download selected release**. The background worker verifies the archive, extracts it safely, retains the complete upstream notices/assets, and records a per-file integrity manifest. Downloading does not restart sites or activate the binary.
3. Select a downloaded version and **Activate downloaded runtime**. The worker checks its integrity and probes startup with the current policies and GeoIP settings before restarting active sites sequentially. An incompatible candidate is rejected before touching production services.
4. **Use automatic** selects the exact version in the extension's `runtime.lock.json` (currently 1.28.1). It downloads the pinned archive if necessary. This does not follow GitHub's latest release. Future extension upgrades follow their new pin only in Automatic mode; an Override remains selected until explicitly changed.
5. **Roll back** selects the previous concrete runtime as an Override. To resume following the extension's default on later upgrades, use **Use automatic**.

Status shows the selected mode/version, packaged pin, previous runtime, cached versions, and background job result. Jobs continue when you close the panel. Refresh status after a connection error; do not replay a mutation automatically. GitHub failures/rate limits retain the last catalog and working runtime. Previously verified cached binaries can be activated or rolled back without GitHub access. No background task automatically discovers, downloads, or activates newer releases; the runtime timer only resumes interrupted jobs.

## What changes during activation

Current extension-generated bot rules, challenge controls, GeoIP sources, image choices, path selection, and nginx routing remain unchanged. Selecting another binary does not import that release's default bot policy. Candidate probes check the version, metrics health endpoint, and challenge image endpoint using each active site's generated policy; they do not replace live browser acceptance checks.

Switches restart protected site services one at a time. The selected per-site fail-open/fail-closed behavior applies during that interruption. Each site service uses a fixed launcher and its own version-pinned environment so restarts during a switch keep the correct binary, policy, and database together. `/var/lib/plesk-anubis/runtime/active` records the global selection; changing it manually is unsupported.

Challenge databases live in `ID/data/runtime-VERSION/challenges.bdb`. A version's first activation creates a fresh database; returning to a version reuses its own data. Legacy `ID/data/challenges.bdb` is moved into the original version namespace only after its service has stopped. Previous databases are retained, so storage may grow with downloaded/used versions. Signing keys are retained; visitor challenge/token behavior can still vary between upstream versions.

## Logs and recovery

```sh
journalctl -u plesk-anubis-runtime.service
journalctl -u 'plesk-anubis@*.service'
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard runtime-status
```

Version selection, release catalog, job status, and the activation recovery journal are root-only under `/var/lib/plesk-anubis/runtime-manager/`. Verified runtimes are under `/var/lib/plesk-anubis/runtime/VERSION/`.

If any service fails during activation, the worker restores the previous selection and affected services. If recovery also fails, it retains the journal and blocks further runtime/site/GeoIP activation. Fix the reported service or filesystem error and run:

```sh
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard reconcile
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard runtime-worker
```

Reconciliation recovers an interrupted switch before normal site handling. The worker also recovers before resuming an interrupted job. Never delete recovery journals, edit selection files, or change symlinks to bypass recovery.

## Staging acceptance

After upgrading the extension, verify these with at least one protected staging site:

- Customers cannot see runtime controls or access either runtime API route. Administrators see Automatic and the packaged pin initially.
- Refresh, download a compatible alternative release, and confirm running services remain unchanged until activation. Verify GitHub rate/network errors preserve the catalog and current runtime.
- Activate it and check the site's browser challenge, selected paths, exclusions, challenge images, and enabled GeoIP behavior. Confirm nginx remains running throughout.
- Roll back while GitHub access is unavailable; verify the previous version and database namespace return. Select Automatic afterward.
- Confirm an incompatible runtime fails its probe without changing live services. On an isolated staging host, inject a service-start failure and interrupt a switch to exercise rollback and reconciliation.
- Upgrade the extension in Override mode and confirm the override persists; repeat in Automatic mode with a changed packaged pin.

Automated tests mock GitHub, systemd, and socket health in this workspace. Live GitHub discovery/download and systemd/browser acceptance must be completed on the Plesk host.
