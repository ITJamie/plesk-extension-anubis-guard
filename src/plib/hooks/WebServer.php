<?php
class Modules_AnubisGuard_WebServer extends pm_Hook_WebServer
{
    public function processTemplate($templateFile, $content, $domain)
    {
        if (!$domain || !preg_match('~(?:^|/)domain/nginxDomainVirtualHost\.php$~', str_replace('\\', '/', $templateFile))) {
            return $content;
        }
        $id = (int) $domain->getId();
        // SDK builds may invoke the hook on source or rendered template content.
        // Wrapping source in try/finally also handles Plesk's early-return branches.
        if (strpos($content, '<?') !== false) {
            return '<?php ob_start(); try { ?>' . $content . '<?php } finally {' .
                ' $__anubisOutput = ob_get_clean();' .
                ' echo Modules_AnubisGuard_Bridge::transform(' . $id . ', ' .
                var_export('domain/nginxDomainVirtualHost.php', true) . ', $__anubisOutput, ' .
                'isset($OPT["ipAddress"], $OPT["backendPort"]) ? [' .
                '(($OPT["ssl"] ?? false) ? "https://" : "http://") . ' .
                '$OPT["ipAddress"]->proxyEscapedAddress . ":" . $OPT["backendPort"]] : []);' .
                ' } ?>';
        }
        $origins = [];
        foreach (array_unique(array_merge(['127.0.0.1', '::1'], $domain->getIpAddresses(false))) as $ip) {
            $host = strpos($ip, ':') !== false ? '[' . $ip . ']' : $ip;
            $origins[] = 'http://' . $host . ':7080';
            $origins[] = 'https://' . $host . ':7081';
        }
        return Modules_AnubisGuard_Bridge::transform($id, 'domain/nginxDomainVirtualHost.php', $content, $origins);
    }

    public function getDomainApacheConfig(pm_Domain $domain)
    {
        return Modules_AnubisGuard_Bridge::transform((int) $domain->getId(), 'apache', '');
    }
}
