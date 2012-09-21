<?php

/**
 * API for simple operations on UF's public directory LDAP server
 *
 * <code>
 * $ldap = Coe_Ldap_Ufdir::factory();
 *
 * $glid = 'sclay';
 *
 * // get attributes
 * $attr = $ldap->getAttributesByGlid('sclay');
 *
 * </code>
 */
class Coe_Ldap_Ufdir extends Coe_Ldap_Ufad
{
    protected $glidKey = 'uid';

    protected $ufidKey = 'uidnumber';

    protected $personsBaseDn = 'OU=People,DC=ufl,DC=edu';

    /**
     * @var string the filter for the findUsers() LDAP query. In this string %QUERY% will be replaced by an
     *             escaped version of the search string passed in as $query.
     */
    public $findUsersfilterFormat = "(|(sn=%QUERY%*)(displayname=%QUERY%*)(mail=%QUERY%*)(uid=%QUERY%*)(uidnumber=%QUERY%))";

    /**
     * @param string $glid
     * @param string $password
     * @param string $reason
     * @return bool
     * @throws Exception
     */
    public function verifyPassword($glid, $password, &$reason = null)
    {
        throw new Exception('not implemented');
    }

    /**
     * @param string $groupCn e.g. THE-GROUP-NAME or CN=THE-GROUP-NAME,OU=...,DC=...
     * @param array $attrs
     * @return bool
     * @throws Exception
     */
    public function isMemberOf($groupCn, array $attrs)
    {
        throw new Exception('not implemented');
    }

    /**
     * @param array $config array with keys:
     *   server : default "ldaps://dir.ufl.edu"
     *   port : default 636
     *   rdn : (R)DN of user to authenticate, default null
     *   password : of user to authenticate, default null
     *   anonymousFallback : automatically bind anonymously if credentials fail, default false
     *
     * @return bool|Coe_Ldap_Ufdir
     */
    static public function factory(array $config = array())
    {
        $config = array_merge(array(
            'server' => 'ldaps://dir.ufl.edu',
            'port' => '636',
        ), $config);
        $ldap = new Coe_Ldap($config);
        $conn = $ldap->getConnection();
        return $conn ? new self($conn) : false;
    }
}
