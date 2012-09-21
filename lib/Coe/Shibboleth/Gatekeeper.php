<?php

/**
 * Acts as a gatekeeper for a PHP shibboleth auth mechanism in a Shibboleth lazy session
 * environment.
 * 
 * <code>
 * $gatekeeper->setRequiredAttrPattern('loa', '@^2$@'); //optional
 * $gatekeeper->protect();
 * // your shibboleth auth adapter here...
 * </code>
 */
class Coe_Shibboleth_Gatekeeper {
    
    /**
     * @param Coe_Shibboleth_Environment $env
     * 
     * @param Coe_Uri $uri
     */
    public function __construct(Coe_Shibboleth_Environment $env = null, Coe_Uri $uri = null)
    {
        if (! $env) {
            $env = new Coe_Shibboleth_Environment();
        }
        $this->_env = $env;
        if (! $uri) {
            $uri = new Coe_Uri();
        }
        $this->_uri = $uri;
        $this->_attrValidator = function ($attrs) { return true; };
    }
    
    /**
     * Set URL to redirect user to if they do not meet the attribute criteria
     * 
     * @param string $url 
     */
    public function setRejectionUrl($url)
    {
        $this->_rejectionUrl = $url;
    }
    
    /**
     * Set function to be called to validate the user's attributes. The attributes will
     * be passed in as the first argument, and the function should return true is the
     * attributes are valid.
     * 
     * @param callback $func 
     */
    public function setAttrValidator($func)
    {
        $this->_attrValidator = $func;
    }
    
    /**
     * Set the attribute validator to a function that checks a particular attribute
     * against a PCRE pattern.
     * 
     * @param string $attrName
     * 
     * @param string $pattern
     */
    public function setRequiredAttrPattern($attrName, $pattern)
    {
        $this->setAttrValidator(function ($attrs) use ($attrName, $pattern) {
            return (isset($attrs[$attrName]) && preg_match($pattern, $attrs[$attrName]));
        });
    }
    
    /**
     * Set the attribute validator to require the user be in a particulat UFAD group.
     * 
     * <code>
     * $gatekeeper->setRequiredAdGroup('CN=COE-SVN,OU=COE-Security Groups,OU=COE,OU=Departments,OU=UF,DC=ad,DC=ufl,DC=edu');
     * </code>
     * 
     * @param string $groupDn 
     * 
     * @param boolean $caseSensitive
     */
    public function setRequiredAdGroup($groupDn, $caseSensitive = false)
    {
        $pattern = '@(^|;)' . preg_quote($groupDn, '@') . '($|;)@';
        if (! $caseSensitive) {
            $pattern .= 'i';
        }
        $this->setRequiredAttrPattern('UFADGroupsDN', $pattern);
    }

    /**
     * If there's no Shibboleth user, redirect to Shibboleth login. If Shibboleth session 
     * is active, validate attributes. If valid, re-inject attrs into $_SERVER (in case
     * mod_rewrite altered the keys). If invalid, redirect to the rejection URL.
     * 
     * @param boolean $shibRequiresHttps set to true if your Shibboleth environment
     * will only release attributes over HTTPS.
     */
    public function protect($shibRequiresHttps = false)
    {
        if ('' === $this->_env->getUsername()) {
            $this->_uri->redirect($this->_env->getLoginUrl($this->_uri, $shibRequiresHttps));
        }
        // we have *some* user
        if (call_user_func($this->_attrValidator, $this->_env->attrs)) {
            // valid!
            $this->_env->injectIntoServer();
        } else {
            // no good
            $url = $this->_rejectionUrl;
            if ($url[0] === '/') {
                $url = $this->_uri->siteRoot . $url;
            }
            $this->_uri->redirect($url);
        }
    }
    
    /**
     * @var Coe_Shibboleth_Environment 
     */
    protected $_env;
    
    /**
     * @var Coe_Uri
     */
    protected $_uri;
    
    /**
     * @var string
     */
    protected $_rejectionUrl = '/';
    
    /**
     * @var callback
     */
    protected $_attrValidator;
}
