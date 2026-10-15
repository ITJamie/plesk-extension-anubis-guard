<?php
/** Plesk owns tenant membership and subscription/user permission decisions. */
class Modules_AnubisGuard_Access
{
    public const PERMISSION = 'manage_protection';

    public static function client()
    {
        $client = pm_Session::getClient();
        if (!$client) {
            throw new pm_Exception('A Plesk login is required.');
        }
        return $client;
    }

    public static function isAdmin(): bool
    {
        return self::client()->isAdmin();
    }

    public static function validDomainId($value): bool
    {
        return (is_int($value) || is_string($value)) &&
            preg_match('/^[1-9][0-9]{0,9}$/D', (string) $value) === 1;
    }

    private static function permitted($client, pm_Domain $domain): bool
    {
        // Visibility callbacks may execute outside the extension's application.
        // Permission names are module-relative, so bind and restore that context.
        $previous = pm_Context::isInitialized() ? pm_Context::getModuleId() : null;
        if ($previous !== 'anubis-guard') {
            pm_Context::init('anubis-guard');
        }
        try {
            return $domain->hasPermission(self::PERMISSION) &&
                $client->hasPermission(self::PERMISSION, $domain);
        } finally {
            if ($previous === null) {
                pm_Context::reset();
            } elseif ($previous !== 'anubis-guard') {
                pm_Context::init($previous);
            }
        }
    }

    public static function canManageDomain($domainId): bool
    {
        if (!self::validDomainId($domainId)) {
            return false;
        }
        $client = self::client();
        if ($client->isAdmin()) {
            return true;
        }
        // Check access before looking up the domain or its settings. This also
        // respects sites delegated by Plesk, rather than trusting a request ID.
        if (!$client->hasAccessToDomain((int) $domainId)) {
            return false;
        }
        try {
            return self::permitted($client, pm_Domain::getByDomainId((int) $domainId));
        } catch (pm_Exception $error) {
            return false;
        }
    }

    public static function allowedDomainIds(): array
    {
        $client = self::client();
        $ids = [];
        foreach (pm_Domain::getAllDomains() as $domain) {
            $id = (int) $domain->getId();
            if ($client->isAdmin() || ($client->hasAccessToDomain($id) && self::permitted($client, $domain))) {
                $ids[] = $id;
            }
        }
        return $ids;
    }
}
