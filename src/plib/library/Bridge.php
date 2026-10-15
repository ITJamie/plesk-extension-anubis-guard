<?php
/** All privileged operations pass through a fixed module helper. */
class Modules_AnubisGuard_Bridge
{
    public static function call(array $arguments, string $input = ''): string
    {
        $result = pm_ApiCli::callSbin('anubis-guard', $arguments, pm_ApiCli::RESULT_FULL, [], $input);
        if ((int) $result['code'] !== 0) {
            throw new pm_Exception(trim($result['stderr']) ?: 'Anubis Guard operation failed; inspect the server journal.');
        }
        return $result['stdout'];
    }

    public static function json(array $arguments, string $input = ''): array
    {
        return json_decode(self::call($arguments, $input), true, 512, JSON_THROW_ON_ERROR);
    }

    public static function transform(int $domainId, string $template, string $content, array $origins = []): string
    {
        return self::call(['render', (string) $domainId, $template, json_encode($origins, JSON_THROW_ON_ERROR)], $content);
    }
}
