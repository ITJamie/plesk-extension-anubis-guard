# GeoIP databases

GeoIP is a server-wide administrator setting. Customers continue to manage their own site protection, challenge, path and failure settings; they cannot access GeoIP settings, database paths, or credentials.

## Choose a source

Open Anubis Guard as the Plesk administrator. In **Server-wide GeoIP databases**, choose:

- **Disabled:** omit the complete country/ASN-dependent rules from the pinned default rule set. Ordinary challenges and other bot rules remain. This is the upgrade default; the server's 2019 OS databases are not adopted automatically.
- **Download from MaxMind:** enter your MaxMind account ID and license key. The worker downloads GeoLite2 Country and ASN over HTTPS. Your account must permit these downloads. Both databases are required. Leaving the key blank retains it; the UI shows only whether one is saved. To remove the key, select Disabled or Local and check **Clear the saved license key**.
- **Use local database files:** enter separate absolute Country and ASN MMDB paths or patterns, for example `/srv/geoip/*/GeoLite2-Country.mmdb` and `/srv/geoip/GeoLite2-ASN_*.mmdb`. Exact paths are also supported. GeoLite2-Country/GeoIP2-Country and GeoLite2-ASN/GeoIP2-ASN types are accepted. City/ISP databases are not accepted as substitutes.

`*` matches within one directory or filename component; `**`, `?`, and bracket expressions are unsupported. Among valid matches of the required database type, the greatest internal build epoch wins, then the lexicographically greatest absolute filename. File modification times do not affect selection. Invalid candidates are ignored and reported. Each pattern is limited to 1000 candidates and each database to 128 MiB. Source files are never modified.

The administrator must provide any public application aliases required by site protection separately; GeoIP sources do not change included paths or exclusions. Activating GeoIP enables the pinned upstream country/network rules, including added suspicion for Brazil/China and selected networks. This is a filtering change, not just a log change.

## Updates and status

**Save GeoIP settings** validates the form and queues a background job. **Refresh databases now** queues a refresh of the active configuration. The UI polls status and never automatically repeats a POST after a connection failure. Use **Refresh GeoIP status** to inspect a possibly completed request.

The five-minute systemd timer checks local patterns each run; MaxMind checks are limited to once per 24 hours, including failed scheduled attempts. Manual refresh bypasses that schedule. Unchanged database contents do not restart Anubis. Failed source changes keep the prior configuration; fix the input and save again. A failed refresh of an already-active source retains that source and its last working snapshots.

Each selected pair is copied into an immutable, root-owned generation under `/var/lib/plesk-anubis/geoip/generations/`. Anubis reads the shared copies through its supplementary group; the original local path need not be accessible inside its systemd sandbox. Snapshots are validated after copying. New and previous generations are retained, and older generations are removed only after successful activation.

Changing databases regenerates policies and restarts eligible active Anubis instances sequentially, with health checks. No nginx regeneration or restart occurs. A site's fail-open/fail-closed setting governs its brief Anubis restart interval. Suspended sites are not started; their policies use the current generation when reconciled or re-enabled. Successful refresh status shows the source, selected filenames and build dates, last check, and last success. Failed updates retain errors until the next successful job.

Anubis memory-maps MMDB files; do not overwrite extension-owned snapshots in place. An external updater should publish complete source files by atomic rename. Copying a partially written source may be rejected and retried at the next scheduled check.

## Credentials and network

Credentials and queued job inputs are root-only files, never command-line arguments or Anubis environment variables. Finished jobs discard private payloads. Status responses and logs do not return the key or signed redirect URL. Downloads use fixed MaxMind endpoints and permit HTTPS redirects only to MaxMind's documented database storage host; authorization is removed when changing hosts. The server needs outbound DNS/HTTPS access. No database is distributed in the extension ZIP.

The supplied AlmaLinux server already has `/usr/bin/mmdblookup` from `libmaxminddb`. Installation checks for that utility. The implementation uses this native reader instead of the initially planned vendored Python reader; there is no new Python package or runtime reader download.

## Recovery

Inspect as root:

```sh
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard geoip-status
journalctl -u plesk-anubis-geoip.service -n 80 --no-pager
systemctl status plesk-anubis-geoip.timer
```

Activation records the previous state, credentials, and affected domains in a root-only journal before changing policies. Failed activation restores them. The regular reconcile worker and GeoIP worker recover interrupted activation before proceeding. If rollback also fails, the journal is retained, new site/GeoIP saves are blocked, and the panel reports recovery is required. Fix service errors and run:

```sh
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard reconcile
systemctl start plesk-anubis-geoip.service
```

Do not delete the journal to force a change. On uninstall the GeoIP timer/worker are stopped, successful recovery completes, and saved credentials/queued payloads are removed; retained snapshots and non-secret settings support recovery or reinstall.

References: [Anubis 1.28.1 GeoIP documentation](https://github.com/TecharoHQ/anubis/blob/v1.28.1/docs/docs/admin/geoip.mdx) and [MaxMind database downloads](https://dev.maxmind.com/geoip/updating-databases/).
