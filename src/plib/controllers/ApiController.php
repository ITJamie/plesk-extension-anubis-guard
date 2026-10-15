<?php
class ApiController extends pm_Controller_Action
{
    public function init()
    {
        parent::init();
        Modules_AnubisGuard_Access::client();
    }

    public function listAction()
    {
        $this->getResponse()->setHeader('Cache-Control', 'no-store', true);
        try {
            $admin = Modules_AnubisGuard_Access::isAdmin();
            if ($admin) {
                $result = Modules_AnubisGuard_Bridge::json(['status']);
            } else {
                $ids = Modules_AnubisGuard_Access::allowedDomainIds();
                $result = Modules_AnubisGuard_Bridge::json(['status-scoped'], json_encode(['ids' => $ids], JSON_THROW_ON_ERROR));
                // Recheck at the response boundary, including permission changes
                // since enumeration. Never expose another tenant's settings.
                $result['domains'] = array_values(array_filter($result['domains'], static function ($domain) use ($ids) {
                    return in_array((int) $domain['id'], $ids, true) &&
                        Modules_AnubisGuard_Access::canManageDomain($domain['id']);
                }));
            }
            $result['is_admin'] = $admin;
            $this->_helper->json($result);
        } catch (Throwable $error) {
            $this->getResponse()->setHttpResponseCode(503);
            $this->_helper->json(['error' => $error->getMessage()]);
        }
    }

    public function geoipstatusAction()
    {
        $this->geoipRequest('geoip-status', false);
    }

    public function runtimestatusAction()
    {
        $this->runtimeRequest(false);
    }

    public function runtimejobAction()
    {
        $this->runtimeRequest(true);
    }

    private function runtimeRequest(bool $mutation): void
    {
        $this->getResponse()->setHeader('Cache-Control', 'no-store', true);
        if (!Modules_AnubisGuard_Access::isAdmin()) {
            $this->getResponse()->setHttpResponseCode(403);
            $this->_helper->json(['error' => 'Only server administrators can manage Anubis runtimes.']);
            return;
        }
        if ($mutation && !$this->getRequest()->isPost()) {
            $this->getResponse()->setHttpResponseCode(405)->setHeader('Allow', 'POST', true);
            $this->_helper->json(['error' => 'Use POST to change Anubis runtimes.']);
            return;
        }
        if ($mutation && !Modules_AnubisGuard_Csrf::isValid((string) $this->getRequest()->getHeader('X-Anubis-CSRF'))) {
            $this->getResponse()->setHttpResponseCode(403);
            $this->_helper->json(['error' => 'The form expired. Reload this page and try again.']);
            return;
        }
        try {
            $input = $mutation ? $this->getRequest()->getRawBody() : '';
            if (strlen($input) > 65536) {
                throw new InvalidArgumentException('Runtime settings payload is too large.');
            }
            $result = Modules_AnubisGuard_Bridge::json([$mutation ? 'runtime-job' : 'runtime-status'], $input);
            $this->getResponse()->setHttpResponseCode($mutation ? 202 : 200);
            $this->_helper->json($result);
        } catch (Throwable $error) {
            $this->getResponse()->setHttpResponseCode(400);
            $this->_helper->json(['error' => $error->getMessage()]);
        }
    }

    public function geoipsaveAction()
    {
        $this->geoipRequest('geoip-save', true);
    }

    public function geoiprefreshAction()
    {
        $this->geoipRequest('geoip-refresh', true);
    }

    private function geoipRequest(string $command, bool $mutation): void
    {
        $this->getResponse()->setHeader('Cache-Control', 'no-store', true);
        if (!Modules_AnubisGuard_Access::isAdmin()) {
            $this->getResponse()->setHttpResponseCode(403);
            $this->_helper->json(['error' => 'Only server administrators can manage GeoIP databases.']);
            return;
        }
        if ($mutation && !$this->getRequest()->isPost()) {
            $this->getResponse()->setHttpResponseCode(405)->setHeader('Allow', 'POST', true);
            $this->_helper->json(['error' => 'Use POST to change GeoIP settings.']);
            return;
        }
        if ($mutation && !Modules_AnubisGuard_Csrf::isValid((string) $this->getRequest()->getHeader('X-Anubis-CSRF'))) {
            $this->getResponse()->setHttpResponseCode(403);
            $this->_helper->json(['error' => 'The form expired. Reload this page and try again.']);
            return;
        }
        try {
            $input = $command === 'geoip-save' ? $this->getRequest()->getRawBody() : '';
            if (strlen($input) > 65536) {
                throw new InvalidArgumentException('GeoIP settings payload is too large.');
            }
            $result = Modules_AnubisGuard_Bridge::json([$command], $input);
            $this->getResponse()->setHttpResponseCode($mutation ? 202 : 200);
            $this->_helper->json($result);
        } catch (Throwable $error) {
            $this->getResponse()->setHttpResponseCode(400);
            $this->_helper->json(['error' => $error->getMessage()]);
        }
    }

    public function saveAction()
    {
        $this->getResponse()->setHeader('Cache-Control', 'no-store', true);
        if (!$this->getRequest()->isPost()) {
            $this->getResponse()->setHttpResponseCode(405)->setHeader('Allow', 'POST', true);
            $this->_helper->json(['error' => 'Use POST to change protection.']);
            return;
        }
        $token = (string) $this->getRequest()->getHeader('X-Anubis-CSRF');
        if (!Modules_AnubisGuard_Csrf::isValid($token)) {
            $this->getResponse()->setHttpResponseCode(403);
            $this->_helper->json(['error' => 'The form expired. Reload this page and try again.']);
            return;
        }
        try {
            $raw = $this->getRequest()->getRawBody();
            if (strlen($raw) > 65536) {
                throw new InvalidArgumentException('Settings payload is too large.');
            }
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($data) || !isset($data['id']) || !Modules_AnubisGuard_Access::validDomainId($data['id'])) {
                throw new InvalidArgumentException('Invalid domain ID.');
            }
            $id = (string) $data['id'];
            unset($data['id']);
            if (!Modules_AnubisGuard_Access::canManageDomain($id)) {
                $this->getResponse()->setHttpResponseCode(403);
                $this->_helper->json(['error' => 'You do not have permission to manage Anubis for this website.']);
                return;
            }
            $this->_helper->json(Modules_AnubisGuard_Bridge::json(['save', $id], json_encode($data, JSON_THROW_ON_ERROR)));
        } catch (Throwable $error) {
            $this->getResponse()->setHttpResponseCode(400);
            $this->_helper->json(['error' => $error->getMessage()]);
        }
    }
}
