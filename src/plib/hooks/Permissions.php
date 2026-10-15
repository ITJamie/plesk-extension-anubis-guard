<?php
class Modules_AnubisGuard_Permissions extends pm_Hook_Permissions
{
    public function getPermissions()
    {
        return [
            Modules_AnubisGuard_Access::PERMISSION => [
                'default' => true,
                'place' => self::PLACE_ADDITIONAL,
                'name' => 'Manage Anubis protection',
                'description' => 'Allow managing Anubis protection and path/IP exclusions for websites in this subscription.',
            ],
        ];
    }
}
