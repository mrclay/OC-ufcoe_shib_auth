<?php

class Coe_Uri {

    /**
     * protocol and host (and port if necessary) of current URL
     * 
     * Adapted from Zend_Controller_Action_Helper_Redirector::_redirect()
     * 
     * @var string e.g. "https://example.org:8080"
     */
    public $siteRoot = null;

    /**
     * path from site root
     * 
     * @var string e.g. /about/us
     */
    public $requestUri = null;

    /**
     * @param array $server (optional) PHP's $_SERVER array
     */
    public function __construct($server = null)
    {
        if (! $server) {
            $server = $_SERVER;
        }
        $this->requestUri = $server['REQUEST_URI'];
        $host  = isset($server['HTTP_HOST']) ? $server['HTTP_HOST'] : $server['SERVER_NAME'];
        $proto = (isset($server['HTTPS']) && $server['HTTPS']!=="off") ? 'https' : 'http';
        $port  = isset($server['SERVER_PORT']) ? $server['SERVER_PORT'] : 80;
        $uri   = $proto . '://' . $host;
        if ((('http' == $proto) && (80 != $port)) || (('https' == $proto) && (443 != $port))) {
            $uri .= ':' . $port;
        }
        $this->siteRoot = $uri;
    }

    /**
     * 307 Redirect
     *
     * @param string $url
     * @param bool $exitAfter call exit() after sending header?
     * @param bool $closeSession close any open session?
     */
    public function redirect($url, $exitAfter = true, $closeSession = true)
    {
        if ($closeSession && session_id()) {
            session_write_close();
        }
        header("Location: $url");
        if ($exitAfter) {
            exit();
        }
    }

    public static function forceHttps(Zend_Controller_Action $ctrl)
    {
        $req = $ctrl->getRequest();
        if (! $req->isSecure()) {
            $uri = new self();
            list(, $noProto) = explode(':', $uri->siteRoot, 2);
            $location = 'https:' . $noProto . $req->getRequestUri();
            $ctrl->getHelper('redirector')->gotoUrlAndExit($location);
        }
    }
}