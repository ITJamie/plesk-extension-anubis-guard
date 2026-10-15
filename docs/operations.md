# Operations

## Inspect

The panel shows per-domain health and the last apply/reconcile error. As root, use:

```sh
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard status
systemctl status plesk-anubis-reconcile.timer
journalctl -u 'plesk-anubis@*.service'
```

For a specific domain ID, inspect `journalctl -u plesk-anubis@ID.service`. Anubis uses an unprivileged service account, private sockets, read-only system paths, a restricted address-family set, and no capabilities.

For server-wide binary downloads, activation, and rollback, see [runtime versions](runtime-versions.md). Worker logs use `journalctl -u plesk-anubis-runtime.service`.

## Recovery

If saving reports a connection interruption, click **Refresh status** and inspect the site's settings before retrying: the server may have completed the save. Do not automatically replay saves. On versions through 0.4.0, saves could hard-restart nginx, dropping the panel's own request when accessed through the port 443 proxy (panel access log HTTP 499 coinciding with nginx stop/start). Upgrade to 0.4.1 or later; generation now suppresses automatic restarts, validates configuration, and gracefully reloads running web servers. Direct panel access on port 8443 avoids the shared nginx proxy during recovery.

If a configuration apply was interrupted:

```sh
/usr/local/psa/admin/sbin/modules/anubis-guard/anubis-guard reconcile
nginx -t
```

Reconcile restores the previous state from `pending.json` before accepting new saves. Do not delete the journal or edit generated nginx files to force a toggle. If recovery fails, use the service journal and Plesk's configuration diagnostics to resolve the underlying error, then run reconcile again.

Anubis failure keeps traffic blocked with 503 by default. The site's **If Anubis is unavailable** option can instead enable fail open: nginx retries transport errors/timeouts against the private site backend, without treating challenge/denial or HTTP error responses as failures. Both modes retain automatic recovery: `systemd` restarts failed processes and the timer retries unhealthy services. Fail open cannot recover a response already being streamed, and requests already sent may not be retryable. An authorized site manager can explicitly disable protection from the panel after the service is restored or while it is down. Administrators retain recovery access even when a customer's plan permission is revoked.

## Customer access

Customers use Anubis Guard in the hosting navigation or a website's Security section. They receive the full site settings interface, including exclusions, for Plesk-authorized domains only. Administrative service lifecycle commands and server files remain available to root/server administrators.

The native **Manage Anubis protection** permission defaults to enabled. To restrict a plan, change that permission in the plan's permissions and apply the normal Plesk subscription synchronization; subscription-specific overrides follow Plesk's usual rules. Existing protected sites remain protected when access is revoked. An administrator can manage them or re-grant customer control.

If an expected site is missing, check its ownership/delegated access, subscription permission, and client's permission. Refresh the panel after permission changes. A stale open page cannot bypass a revoked permission: the save endpoint rechecks it.

## Backup, upgrade, and uninstall

Back up `/var/lib/plesk-anubis` together with the Plesk configuration, and protect that backup as secret material. This includes domain settings, signing keys, and challenge databases. Stop the affected Anubis processes or use a consistent filesystem snapshot when copying live bbolt files.

Install a newer version through Plesk's extension update/upload flow. Keep the prior release ZIP and a consistent state backup available for rollback. Staging upgrade acceptance is mandatory before a public release; this preview has not been exercised against the live Plesk installer.

The pre-uninstall hook disables protected domains and regenerates normal routing before removing systemd resources. An uninstall error must be resolved before deleting the extension files. Settings and challenge data remain under `/var/lib/plesk-anubis` for recovery/reinstallation; deleted Plesk domains are cleaned by reconciliation. The service account is retained to avoid UID reuse while retained data exists.

## Compatibility failures

Unknown nginx includes and custom real-IP configuration require a reviewed adapter. The extension reports these rather than attempting incomplete protection. Test coexistence with nginx WAF, SSL It!/Let's Encrypt, Node.js, WordPress Toolkit, and other installed extensions that change a site's routing.

This first release does not configure CDN trust, change global Apache ports, disable SELinux, manage panel certificates, or alter mail/webmail protection.
