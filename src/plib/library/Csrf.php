<?php
/** Store CSRF state in the PHP session that Plesk has already authenticated. */
class Modules_AnubisGuard_Csrf
{
    private const KEY = 'anubis_guard_csrf';

    public static function token(): string
    {
        // Zend_Session_Namespace attempts to start a second session on current
        // Plesk builds. Never start or reconfigure the host's session here.
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new pm_Exception('The Plesk session is unavailable. Reload the panel and try again.');
        }
        if (!isset($_SESSION[self::KEY]) || !is_string($_SESSION[self::KEY]) ||
            !preg_match('/^[a-f0-9]{64}$/D', $_SESSION[self::KEY])) {
            $_SESSION[self::KEY] = bin2hex(random_bytes(32));
        }
        return $_SESSION[self::KEY];
    }

    public static function isValid(string $token): bool
    {
        return session_status() === PHP_SESSION_ACTIVE &&
            isset($_SESSION[self::KEY]) && is_string($_SESSION[self::KEY]) &&
            $token !== '' && hash_equals($_SESSION[self::KEY], $token);
    }
}
