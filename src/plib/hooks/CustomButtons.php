<?php
class Modules_AnubisGuard_CustomButtons extends pm_Hook_CustomButtons
{
    public function getButtons()
    {
        return [[
            'place' => self::PLACE_HOSTING_PANEL_NAVIGATION,
            'section' => self::SECTION_NAV_ADDITIONAL,
            'title' => 'Anubis Guard',
            'icon' => pm_Context::getBaseUrl() . 'images/anubis-guard.svg',
            'description' => 'Manage website bot protection and exclusions.',
            'link' => pm_Context::getBaseUrl() . 'index.php/index/index',
            'newWindow' => false,
            'visibility' => [$this, 'isVisible'],
        ], [
            'place' => self::PLACE_DOMAIN_PROPERTIES_DYNAMIC,
            'section' => self::SECTION_DOMAIN_PROPS_DYNAMIC_SECURITY,
            'title' => 'Anubis Guard',
            'icon' => pm_Context::getBaseUrl() . 'images/anubis-guard.svg',
            'description' => 'Manage bot protection and exclusions for this website.',
            'link' => pm_Context::getBaseUrl() . 'index.php/index/index',
            'newWindow' => false,
            'contextParams' => true,
            'visibility' => [$this, 'isDomainVisible'],
        ]];
    }

    public function isVisible($options = []): bool
    {
        try {
            return Modules_AnubisGuard_Access::isAdmin() || Modules_AnubisGuard_Access::allowedDomainIds() !== [];
        } catch (pm_Exception $error) {
            return false;
        }
    }

    public function isDomainVisible($options): bool
    {
        try {
            return is_array($options) && empty($options['alias_id']) &&
                isset($options['site_id']) && Modules_AnubisGuard_Access::canManageDomain($options['site_id']);
        } catch (pm_Exception $error) {
            return false;
        }
    }
}
