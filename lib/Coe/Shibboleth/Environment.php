<?php

/**
 * Use this to find the current user's identity instead of sniffing $_SERVER
 *
 * You'll probably want to extend this class for other Shibboleth IdPs
 */
class Coe_Shibboleth_Environment {
    protected $_keys = 'glid,ufid,cn,sn,givenName,middleName,mail,businessName,UFAD_Groups,UFADGroupsDN,eduperson_affiliations,loa,postalAddress,primary-affiliation,uf_affiliations';

    public $attrs = array();

    public $loginUri = '/Shibboleth.sso/Login';

    public function __construct($server = null, $applyUfHacks = true)
    {
        if (! $server) {
            $server = $_SERVER;
        }
        $keys = explode(',', $this->_keys);
        // handle keys from mod_rewrite
        foreach ($keys as $key) {
            if (isset($server['REDIRECT_' . $key])) {
                $server[$key] = $server['REDIRECT_' . $key];
            }
        }
        if ($applyUfHacks) {
            if (empty($server['glid']) && ! empty($server['PHP_AUTH_USER']) && preg_match('/^([^@]+)@ufl\\.edu$/', $server['PHP_AUTH_USER'], $m)) {
                $server['glid'] = $m[1];
            }
            if (empty($server['cn'])) {
                if (! empty($server['businessName'])) {
                    $server['cn'] = $server['businessName'];
                } elseif (! empty($server['sn']) && ! empty($server['givenName'])) {
                    $server['cn'] = $server['sn'] . ',' . $server['givenName'];
                }
            }
            if (empty($server['mail'])) {
                if (! empty($server['eppn'])) {
                    $server['mail'] = $server['eppn'];
                } elseif (! empty($server['glid'])) {
                    $server['mail'] = "{$server['glid']}@ufl.edu";
                }
            }
        }
        foreach ($keys as $key) {
            $this->attrs[$key] = isset($server[$key]) ? $server[$key] : '';
        }
    }

    public function getUsername()
    {
        return $this->attrs['glid'];
    }

    public function getEmail()
    {
        return $this->attrs['mail'];
    }

    public function getName()
    {
        $cn = $this->attrs['cn'];
        if (! $cn) {
            return '';
        }
        if (false !== strpos($cn, ',')) {
            // has comma
            list($last, $first) = explode(',', $cn, 2);
            return trim($first) . ' ' . trim($last);
        } else {
            return trim($cn);
        }
    }

    /**
     * Get URL to redirect to in order to force the user to login
     * 
     * @param Coe_Uri $uri
     * 
     * @param boolean $targetIsHttps set to true if your Shibboleth environment
     * will only release attributes over HTTPS.
     * 
     * @return string
     */
    public function getLoginUrl(Coe_Uri $uri, $targetIsHttps = false)
    {
        $loginUrl = $this->loginUri;
        if ($loginUrl[0] === '/') {
            $loginUrl = $uri->siteRoot . $loginUrl;
        }
        $target = $uri->siteRoot;
        if ($targetIsHttps) {
            if (0 === strpos($target, 'http://')) {
                $target = 'https://' . substr($target, 7);
            }
            $target = preg_replace('@:\\d+$@', '', $target);
        }
        $target .= $uri->requestUri;
        return $loginUrl . '?target=' . urlencode($target);
    }
    
    /**
     * If GLID found, inject all attrs into $_SERVER
     */
    public function injectIntoServer()
    {
        if ($this->attrs['glid'] !== '') {
            foreach ($this->attrs as $key => $val) {
                $_SERVER[$key] = $val;
            }    
        }
    }
}