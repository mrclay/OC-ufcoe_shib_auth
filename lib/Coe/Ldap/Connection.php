<?php

class Coe_Ldap_Connection
{
    /**
     * @link http://www.php.net/manual/en/function.ldap-bind.php#103034
     */
    const OPT_DIAGNOSTIC_MESSAGE = 0x0032;

    const FIELD_DN = 'distinguishedname';

    /**
     * @var resource
     */
    protected $link;

    /**
     * @var string
     */
    protected $boundRdn = '';

    /**
     * @var string
     */
    protected $boundPassword = '';

    /**
     * @var bool
     */
    protected $isBound = false;

    /**
     * @param string $server
     * @param int $port
     * @throws Exception
     */
    public function __construct($server, $port = 389)
    {
        $this->link = @ldap_connect($server, $port);
        if (! $this->link) {
            throw new Exception("Could not connect to $server on port $port");
        }
        ldap_set_option($this->link, LDAP_OPT_PROTOCOL_VERSION, 3);
    }

    /**
     * @return resource
     */
    public function getLink()
    {
        return $this->link;
    }

    /**
     * @param string $rdn
     * @param string $password
     * @return bool
     */
    public function bind($rdn = null, $password = null)
    {
        $success = @ldap_bind($this->link, $rdn, $password);
        if ($success) {
            $this->isBound = true;
            $this->boundRdn = $rdn;
            $this->boundPassword = $password;
        } else {
            $this->isBound = false;
            $this->boundRdn = '';
        }
        return $success;
    }

    /**
     * Verify a user can bind. The connection will re-bind to the previous user if was already bound.
     *
     * @param string $dn
     * @param string $password
     * @return bool
     */
    public function canBind($dn, $password)
    {
        $wasBound = $this->isBound;
        $currentRdn = $this->boundRdn;
        $currentPassword = $this->boundPassword;

        // check given credentials
        $res = (bool) @ldap_bind($this->link, $dn, $password);

        if ($wasBound) {
            // rebind with previous credentials
            $this->bind($currentRdn, $currentPassword);
        }
        return $res;
    }

    /**
     * @return bool
     */
    public function isBound() {
        return $this->isBound;
    }

    /**
     * @return string
     */
    public function getBoundRdn() {
        return $this->boundRdn;
    }

    /**
     * Escape a string for use in an LDAP filter
     *
     * @see http://us3.php.net/manual/en/function.ldap-search.php#90158
     * @param string $str
     * @param bool $for_dn
     * @return string
     */
    public function escape($str, $for_dn = false)
    {
        // see:
        // RFC2254
        // http://msdn.microsoft.com/en-us/library/ms675768(VS.85).aspx
        // http://www-03.ibm.com/systems/i/software/ldap/underdn.html
        $metaChars = ($for_dn)
            ? array(',','=', '+', '<','>',';', '\\', '"', '#')
            : array('*', '(', ')', '\\', chr(0));
        $quotedMetaChars = array();
        foreach ($metaChars as $key => $value) {
            $quotedMetaChars[$key] = '\\'.str_pad(dechex(ord($value)), 2, '0');
        }
        return str_replace($metaChars, $quotedMetaChars, $str);
    }

    /**
     * Fetch an LDAP record (into $this->results) from a filter
     *
     * @param string $filter LDAP filter
     * @param string $scope DN to search over
     * @param array $attributes attributes requested
     * @param int $limit
     * @return bool|Coe_Ldap_Result
     */
    public function query($filter, $scope, $attributes = array(), $limit = 200)
    {
        // This performs the search for a specified filter on the directory with the scope of LDAP_SCOPE_SUBTREE
        // error suppression added because ldap_search throws WARNINGs when the search limit is hit
        $result = @ldap_search($this->link, $scope, $filter, $attributes, 0, $limit);
        if (! $result) {
            return false;
        }
        return new Coe_Ldap_Result($this->link, $result);
    }

    /**
     * Get the last error
     *
     * @param bool $getExtended
     * @return array
     */
    public function getError($getExtended = true)
    {
        $ret = array(
            'error' => ldap_error($this->link),
            'errno' => ldap_errno($this->link),
        );
        if ($getExtended && ldap_get_option($this->link, self::OPT_DIAGNOSTIC_MESSAGE, $extendedError)) {
            $ret['error_extended'] = $extendedError;
        }
        return $ret;
    }
}