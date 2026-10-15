<?php
class IndexController extends pm_Controller_Action
{
    public function init()
    {
        parent::init();
        Modules_AnubisGuard_Access::client();
    }

    public function indexAction()
    {
        $this->view->pageTitle = 'Anubis Guard';
        $this->view->isAdmin = Modules_AnubisGuard_Access::isAdmin();
        $this->view->baseUrl = pm_Context::getBaseUrl();
        $siteId = $this->getRequest()->getParam('site_id');
        if ($siteId !== null && !Modules_AnubisGuard_Access::canManageDomain($siteId)) {
            $this->getResponse()->setHttpResponseCode(403);
            throw new pm_Exception('You do not have permission to manage Anubis for this website.');
        }
        $this->view->domainId = $siteId === null ? '' : (string) $siteId;
        $this->view->csrf = Modules_AnubisGuard_Csrf::token();
        $this->view->headLink()->appendStylesheet(pm_Context::getBaseUrl() . 'dist/app.css?v=0.8.1');
        $this->view->headScript()->appendFile(pm_Context::getBaseUrl() . 'dist/app.js?v=0.8.1');
    }
}
