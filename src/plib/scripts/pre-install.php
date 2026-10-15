<?php
pm_Context::init('anubis-guard');
// The helper is not extracted yet. Validate without modifying the server.
$release = parse_ini_file('/etc/os-release');
if (($release['ID'] ?? '') !== 'almalinux' || !str_starts_with($release['VERSION_ID'] ?? '', '9.')) {
    throw new pm_Exception('Anubis Guard 0.1 supports AlmaLinux 9 only.');
}
if (php_uname('m') !== 'x86_64' || !is_file('/etc/nginx/nginx.conf')) {
    throw new pm_Exception('Anubis Guard requires x86_64 and the Plesk nginx component.');
}
