<?php
/** SDK boundary tests use stubs; they do not pretend to boot Plesk. */
// Reproduce Plesk starting a native session before extension controllers run.
ini_set('session.use_cookies', '0');
session_cache_limiter('');
session_save_path(sys_get_temp_dir());
session_id('anubis-test-' . bin2hex(random_bytes(12)));
session_start();
class pm_Exception extends Exception {}
class pm_Hook_WebServer {}
class pm_Hook_Permissions { public const PLACE_ADDITIONAL = 'additional'; }
class pm_Hook_CustomButtons
{
    public const PLACE_HOSTING_PANEL_NAVIGATION = 7;
    public const SECTION_NAV_ADDITIONAL = 'custom_buttons';
    public const PLACE_DOMAIN_PROPERTIES_DYNAMIC = 16;
    public const SECTION_DOMAIN_PROPS_DYNAMIC_SECURITY = 'security';
}
class pm_Domain
{
    public static array $records = [7, 8];
    public static array $permissions = [7 => true, 8 => true];
    public static bool $throwPermission = false;
    private int $id;
    public function __construct($id = 7)
    {
        if (!in_array((int) $id, self::$records, true)) { throw new pm_Exception('Unknown domain'); }
        $this->id = (int) $id;
    }
    public static function getByDomainId($id) { return new self($id); }
    public static function getAllDomains() { return array_map(static fn ($id) => new self($id), self::$records); }
    public function getId() { return $this->id; }
    public function getIpAddresses($public) { return ['192.0.2.1']; }
    public function hasPermission($name)
    {
        if (self::$throwPermission) { throw new pm_Exception('Permission lookup unavailable'); }
        return pm_Context::getModuleId() === 'anubis-guard' && $name === 'manage_protection' && (self::$permissions[$this->id] ?? false);
    }
}
class Modules_AnubisGuard_Bridge
{
    public static array $calls = [];
    public static function transform(int $id, string $template, string $content): string
    {
        self::$calls[] = [$id, $template, $content];
        return '[' . $content . ']';
    }
    public static function json(array $args, string $input = ''): array
    {
        self::$calls[] = [$args, $input];
        if (in_array($args[0], ['status', 'status-scoped'], true)) {
            // Deliberately return an out-of-scope row: the API must still filter it.
            return ['domains' => [
                ['id' => 7, 'name' => 'owned.test', 'paths' => ['/owned/'], 'ips' => []],
                ['id' => 8, 'name' => 'other-tenant.test', 'paths' => ['/private/'], 'ips' => []],
            ], 'runtime_version' => '1.28.1'];
        }
        return ['ok' => true];
    }
}
require __DIR__ . '/../src/plib/hooks/WebServer.php';
$checks = 0;
function check(bool $value, string $message): void
{
    global $checks;
    if (!$value) { throw new Exception($message); }
    ++$checks;
}
$hook = new Modules_AnubisGuard_WebServer();
$domain = new pm_Domain();
check($hook->processTemplate('other.php', 'unchanged', $domain) === 'unchanged', 'Unrelated templates changed');
check($hook->processTemplate('domain/nginxDomainVirtualHost.php', 'server {}', null) === 'server {}', 'Domain-less template changed');
check($hook->processTemplate('domain/nginxDomainVirtualHost.php', 'server {}', $domain) === '[server {}]', 'Rendered template hook failed');
foreach (['<?php echo "first"; return; ?>never', '<?php echo "normal"; ?>'] as $source) {
    $wrapped = $hook->processTemplate('/templates/default/domain/nginxDomainVirtualHost.php', $source, $domain);
    ob_start();
    (static function ($template) { eval('?>' . $template); })($wrapped);
    $result = ob_get_clean();
    check($result === (str_contains($source, 'return;') ? '[first]' : '[normal]'), 'Source hook or early return handling failed');
}

class FakeRequest
{
    public bool $post = true;
    public string $token = 'valid-token';
    public string $body = '{"id":7,"enabled":true,"paths":[],"ips":[]}';
    public array $params = [];
    public function isPost() { return $this->post; }
    public function getHeader($name) { return $this->token; }
    public function getRawBody() { return $this->body; }
    public function getParam($name, $default = null) { return $this->params[$name] ?? $default; }
}
class FakeResponse
{
    public int $code = 200;
    public function setHttpResponseCode($code) { $this->code = $code; return $this; }
    public function setHeader(...$args) { return $this; }
}
class FakeHelper
{
    public array $result;
    public function json($result) { $this->result = $result; }
}
class FakeView
{
    public bool $isAdmin;
    public function escape($value) { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
    public function renderIndex()
    {
        ob_start();
        include __DIR__ . '/../src/plib/views/scripts/index/index.phtml';
        return ob_get_clean();
    }
    public string $pageTitle;
    public string $baseUrl;
    public string $csrf;
    public string $domainId;
    public function headLink() { return $this; }
    public function headScript() { return $this; }
    public function appendStylesheet($url) { return $this; }
    public function appendFile($url) { return $this; }
}
class pm_Context
{
    public static ?string $module = 'anubis-guard';
    public static function getBaseUrl() { return '/modules/anubis-guard/'; }
    public static function isInitialized() { return self::$module !== null; }
    public static function getModuleId() { return self::$module; }
    public static function init($module) { self::$module = $module; }
    public static function reset() { self::$module = null; }
}
class pm_Controller_Action
{
    public FakeRequest $request;
    public FakeResponse $response;
    public FakeHelper $_helper;
    public FakeView $view;
    public function __construct() { $this->request = new FakeRequest(); $this->response = new FakeResponse(); $this->_helper = new FakeHelper(); $this->view = new FakeView(); }
    public function init() {}
    public function getRequest() { return $this->request; }
    public function getResponse() { return $this->response; }
}
class FakeClient
{
    public function isAdmin() { return pm_Session::$admin; }
    public function hasAccessToDomain($id) { return in_array((int) $id, pm_Session::$accessible, true); }
    public function hasPermission($name, $domain) { return $name === 'manage_protection' && (pm_Session::$permissions[$domain->getId()] ?? false); }
}
class pm_Session
{
    public static bool $admin = true;
    public static array $accessible = [7];
    public static array $permissions = [7 => true, 8 => true];
    public static function getClient() { return new FakeClient(); }
}
class Zend_Session_Namespace
{
    public function __construct($name)
    {
        throw new Exception('session has already been started by session.auto-start or session_start()');
    }
}
require __DIR__ . '/../src/plib/library/Csrf.php';
require __DIR__ . '/../src/plib/library/Access.php';
$sessionId = session_id();
$csrf = Modules_AnubisGuard_Csrf::token();
check(strlen($csrf) === 64 && ctype_xdigit($csrf), 'CSRF token must have 256 bits of randomness');
check(Modules_AnubisGuard_Csrf::token() === $csrf, 'CSRF token changed across page loads');
check(session_id() === $sessionId && session_status() === PHP_SESSION_ACTIVE, 'Host session changed');
check(!Modules_AnubisGuard_Csrf::isValid(''), 'Empty CSRF accepted');
check(!Modules_AnubisGuard_Csrf::isValid('invalid'), 'Invalid CSRF accepted');
check(Modules_AnubisGuard_Csrf::isValid($csrf), 'Valid native-session CSRF rejected');
require __DIR__ . '/../src/plib/controllers/IndexController.php';
$page = new IndexController();
$page->init();
$page->indexAction();
check($page->view->csrf === $csrf, 'Opening the extension did not reuse the active session');
check(session_id() === $sessionId, 'Opening the extension replaced the host session');
// Render the actual template for both entry points and account types.
foreach ([true, false] as $admin) {
    foreach (['', '7'] as $domainId) {
        $view = new FakeView();
        $view->isAdmin = $admin; $view->domainId = $domainId;
        $view->baseUrl = '/modules/anubis-guard/'; $view->csrf = $csrf;
        $html = $view->renderIndex();
        foreach (['ag-runtime', 'ag-geoip'] as $section) {
            check(str_contains($html, 'id="' . $section . '"') === ($admin && $domainId === ''),
                'Server-wide section visibility is incorrect: ' . $section);
        }
        check(str_contains($html, 'id="ag-domains"') && str_contains($html, 'data-domain-id="' . $domainId . '"'),
            'Site controls or site focus were lost');
    }
}
require __DIR__ . '/../src/plib/controllers/ApiController.php';
pm_Session::$admin = false;
$api = new ApiController();
$api->init();
$api->listAction();
check(array_column($api->_helper->result['domains'], 'id') === [7], 'Customer can see another tenant domain');
check($api->_helper->result['is_admin'] === false, 'Customer was labeled administrator');
$lastCall = end(Modules_AnubisGuard_Bridge::$calls);
check($lastCall[0] === ['status-scoped'] && json_decode($lastCall[1], true) === ['ids' => [7]], 'Privileged status was not scoped to authorized sites');
$api = new ApiController(); $api->request->token = $csrf;
$api->request->body = '{"id":7,"enabled":true,"paths":["/api/"],"ips":["192.0.2.0/24"]}';
$api->saveAction();
check($api->_helper->result === ['ok' => true], 'Customer cannot save own-domain settings');
$lastCall = end(Modules_AnubisGuard_Bridge::$calls);
check($lastCall[0] === ['save', '7'] && json_decode($lastCall[1], true)['paths'] === ['/api/'] &&
    json_decode($lastCall[1], true)['ips'] === ['192.0.2.0/24'], 'Customer exclusions were removed');
$api = new ApiController(); $api->request->token = $csrf;
$api->request->body = '{"id":7,"enabled":false,"paths":[],"ips":[]}';
$api->saveAction();
$lastCall = end(Modules_AnubisGuard_Bridge::$calls);
check($api->_helper->result === ['ok' => true] && json_decode($lastCall[1], true)['enabled'] === false,
    'Customer cannot disable protection for own site');
foreach ([8, 99] as $deniedId) {
    $api = new ApiController(); $api->request->token = $csrf;
    $api->request->body = json_encode(['id' => $deniedId, 'enabled' => false, 'paths' => [], 'ips' => []]);
    $before = count(Modules_AnubisGuard_Bridge::$calls);
    $api->saveAction();
    check($api->response->code === 403, 'Unauthorized/unknown domain mutation was accepted');
    check(count(Modules_AnubisGuard_Bridge::$calls) === $before, 'Unauthorized mutation reached the root helper');
}
$page = new IndexController(); $page->request->params = ['site_id' => '7'];
$page->init(); $page->indexAction();
check($page->view->domainId === '7', 'Domain button did not focus the authorized website');
$page = new IndexController(); $page->request->params = ['site_id' => '8'];
try { $page->indexAction(); throw new Exception('Unauthorized domain page was accepted'); }
catch (pm_Exception $error) { check($page->response->code === 403, 'Unauthorized domain page must receive 403'); }

require __DIR__ . '/../src/plib/hooks/Permissions.php';
require __DIR__ . '/../src/plib/hooks/CustomButtons.php';
$permission = (new Modules_AnubisGuard_Permissions())->getPermissions()['manage_protection'];
check($permission['default'] === true, 'Customer permission should be enabled by default');
$buttons = new Modules_AnubisGuard_CustomButtons();
check($buttons->isVisible() && $buttons->isDomainVisible(['site_id' => 7]), 'Authorized customer entry points are hidden');
check(!$buttons->isDomainVisible(['site_id' => 8]), 'Another tenant domain button is visible');
check(!$buttons->isDomainVisible(['site_id' => 7, 'alias_id' => 4]), 'Alias should use its hosting domain controls');
check(count($buttons->getButtons()) === 2, 'Missing hosting navigation or domain security button');
pm_Context::init('other-extension');
check($buttons->isDomainVisible(['site_id' => 7]), 'Permission checked in the wrong extension context');
check(pm_Context::getModuleId() === 'other-extension', 'Visibility callback changed the host module context');
pm_Context::reset();
check($buttons->isDomainVisible(['site_id' => 7]) && !pm_Context::isInitialized(), 'Callback did not restore an uninitialized context');
pm_Context::init('other-extension');
pm_Domain::$throwPermission = true;
check(!$buttons->isVisible(), 'Permission lookup failure should hide the customer entry point');
check(pm_Context::getModuleId() === 'other-extension', 'Failed lookup did not restore the host module context');
pm_Domain::$throwPermission = false;
pm_Context::init('anubis-guard');

foreach (['subscription', 'client'] as $denyAt) {
    pm_Domain::$permissions[7] = $denyAt !== 'subscription';
    pm_Session::$permissions[7] = $denyAt !== 'client';
    $api = new ApiController(); $api->listAction();
    check($api->_helper->result['domains'] === [], 'Denied plan/client permission leaked domain settings');
    check(!$buttons->isVisible() && !$buttons->isDomainVisible(['site_id' => 7]), 'Denied plan/client permission left entry points visible');
    $api = new ApiController(); $api->request->token = $csrf;
    $before = count(Modules_AnubisGuard_Bridge::$calls);
    $api->saveAction();
    check($api->response->code === 403 && count(Modules_AnubisGuard_Bridge::$calls) === $before,
        'Denied plan/client permission reached the mutation helper');
}
pm_Domain::$permissions[7] = true;
pm_Session::$permissions[7] = true;
check(Modules_AnubisGuard_Access::canManageDomain(7), 'Re-granted permission is not effective');
pm_Session::$accessible = [8];
$api = new ApiController(); $api->listAction();
check(array_column($api->_helper->result['domains'], 'id') === [8], 'Second customer scope was not isolated');
check(!Modules_AnubisGuard_Access::canManageDomain(7), 'Second customer can access first customer site');
pm_Session::$accessible = [7, 8];
$api = new ApiController(); $api->listAction();
check(array_column($api->_helper->result['domains'], 'id') === [7, 8], 'Plesk-delegated sites are not accessible');
foreach ([true, 7.0, '07', '7;id', '-1'] as $badId) {
    check(!Modules_AnubisGuard_Access::validDomainId($badId), 'Noncanonical domain ID accepted');
}
pm_Session::$admin = true;
$api = new ApiController(); $api->listAction();
check(array_column($api->_helper->result['domains'], 'id') === [7, 8] && $api->_helper->result['is_admin'], 'Admin lost global visibility');
pm_Domain::$permissions[7] = false;
pm_Session::$permissions[7] = false;
check(Modules_AnubisGuard_Access::canManageDomain(7), 'Admin recovery should not depend on customer plan permission');
$api = new ApiController(); $api->init();
$api->request->post = false; $api->saveAction();
check($api->response->code === 405, 'GET mutation accepted');
$api = new ApiController(); $api->request->token = 'bad'; $api->saveAction();
check($api->response->code === 403, 'Invalid CSRF accepted');
$api = new ApiController(); $api->request->token = $csrf; $api->request->body = '{"id":"7;whoami"}'; $api->saveAction();
check($api->response->code === 400, 'Invalid domain ID accepted');
$api = new ApiController(); $api->request->token = $csrf; $api->saveAction();
check($api->_helper->result === ['ok' => true], 'Valid save failed');
// Server-wide GeoIP data must never be available through customer permissions.
foreach (['geoipstatusAction', 'geoipsaveAction', 'geoiprefreshAction'] as $action) {
    pm_Session::$admin = false;
    $api = new ApiController(); $api->request->token = $csrf;
    $before = count(Modules_AnubisGuard_Bridge::$calls);
    $api->$action();
    check($api->response->code === 403 && count(Modules_AnubisGuard_Bridge::$calls) === $before,
        'Customer reached server-wide GeoIP data or helper');
}
pm_Session::$admin = true;
foreach (['geoipsaveAction', 'geoiprefreshAction'] as $action) {
    $api = new ApiController(); $api->request->post = false;
    $before = count(Modules_AnubisGuard_Bridge::$calls);
    $api->$action();
    check($api->response->code === 405 && count(Modules_AnubisGuard_Bridge::$calls) === $before, 'GeoIP accepted GET mutation');
    $api = new ApiController(); $api->request->token = 'invalid'; $api->$action();
    check($api->response->code === 403 && count(Modules_AnubisGuard_Bridge::$calls) === $before, 'GeoIP accepted invalid CSRF');
    $api = new ApiController(); $api->request->token = $csrf; $api->request->body = '{"mode":"disabled"}'; $api->$action();
    check($api->response->code === 202, 'GeoIP mutation did not queue asynchronously');
    $args = Modules_AnubisGuard_Bridge::$calls[array_key_last(Modules_AnubisGuard_Bridge::$calls)];
    check($args[0] === [$action === 'geoipsaveAction' ? 'geoip-save' : 'geoip-refresh'], 'GeoIP selected the wrong privileged command');
    check($args[1] === ($action === 'geoipsaveAction' ? '{"mode":"disabled"}' : ''), 'GeoIP passed unexpected helper input');
}
$api = new ApiController(); $api->geoipstatusAction();
check($api->response->code === 200, 'Admin cannot read GeoIP status');
$api = new ApiController(); $api->request->token = $csrf; $api->request->body = str_repeat('x', 65537);
$before = count(Modules_AnubisGuard_Bridge::$calls); $api->geoipsaveAction();
check($api->response->code === 400 && count(Modules_AnubisGuard_Bridge::$calls) === $before, 'Oversized GeoIP settings reached helper');
foreach (['runtimestatusAction', 'runtimejobAction'] as $action) {
    pm_Session::$admin = false;
    $api = new ApiController(); $api->request->token = $csrf;
    $before = count(Modules_AnubisGuard_Bridge::$calls); $api->$action();
    check($api->response->code === 403 && count(Modules_AnubisGuard_Bridge::$calls) === $before, 'Customer reached runtime manager');
}
pm_Session::$admin = true;
$api = new ApiController(); $api->request->post = false; $api->runtimejobAction();
check($api->response->code === 405, 'Runtime GET mutation accepted');
$api = new ApiController(); $api->request->token = 'invalid'; $api->runtimejobAction();
check($api->response->code === 403, 'Runtime invalid CSRF accepted');
$api = new ApiController(); $api->request->token = $csrf; $api->request->body = '{"action":"activate","mode":"automatic"}'; $api->runtimejobAction();
check($api->response->code === 202, 'Runtime mutation was not asynchronous');
$call = Modules_AnubisGuard_Bridge::$calls[array_key_last(Modules_AnubisGuard_Bridge::$calls)];
check($call === [['runtime-job'], '{"action":"activate","mode":"automatic"}'], 'Runtime helper arguments changed');
$api = new ApiController(); $api->runtimestatusAction();
check($api->response->code === 200, 'Admin runtime status failed');
$api = new ApiController(); $api->request->token = $csrf; $api->request->body = str_repeat('x', 65537);
$before = count(Modules_AnubisGuard_Bridge::$calls); $api->runtimejobAction();
check($api->response->code === 400 && count(Modules_AnubisGuard_Bridge::$calls) === $before, 'Oversized runtime request reached helper');
session_destroy();
check(!Modules_AnubisGuard_Csrf::isValid($csrf), 'CSRF accepted without an active host session');
try { Modules_AnubisGuard_Csrf::token(); throw new Exception('Missing session was accepted'); }
catch (pm_Exception $error) { check(session_status() !== PHP_SESSION_ACTIVE, 'CSRF helper started a session'); }
echo "$checks PHP boundary checks passed\n";
