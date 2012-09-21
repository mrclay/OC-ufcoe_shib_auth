<?php

/**
 * API for simple operations on UF's AD LDAP server
 *
 * <code>
 * $ldap = Coe_Ldap_Ufad::factory(array(
 *     'rdn' => 'CN=...,OU=Service Accounts,OU=...,OU=Departments,OU=UF,DC=ad,DC=ufl,DC=edu',
 *     'password => '...',
 * ));
 *
 * // authenticate a user
 * $isCorrectPassword = $ldap->verifyPassword($glid, $password);
 *
 * // get attributes
 * $attr = $ldap->getAttributesByGlid('alberta');
 *
 * // test attributes for group membership
 * $isMember = $ldap->isMemberOf('EDA6931_116G_20128', $attrs);
 *
 * </code>
 */
class Coe_Ldap_Ufad
{
    protected $glidKey = 'samaccountname';

    protected $ufidKey = 'employeeid';

    protected $dnKey = 'distinguishedname';

    /**
     * @var string base DN over which users will be searched
     */
    protected $personsBaseDn = 'OU=People,OU=UF,DC=ad,DC=ufl,DC=edu';

    /**
     * @var Coe_Ldap_Connection
     */
    protected $conn;

    /**
     * @var string the filter for the findUsers() LDAP query. In this string %QUERY% will be replaced by an
     *             escaped version of the search string passed in as $query.
     */
    public $findUsersfilterFormat = "(|(sn=%QUERY%*)(displayname=%QUERY%*)(name=%QUERY%*)(mail=%QUERY%*)(samaccountname=%QUERY%*)(employeeid=%QUERY%))";

    /**
     * @var array the LDAP attributes to return with each user
     */
    public $findUsersReturnedAttributes = array("displayname", "title", "name", "samaccountname", "department",
                                                "mail", "distinguishedname", "givenname", "sn", "employeeid");

    public $userAttributesToRemove = array("objectguid", "objectsid", "msexchsafesendershash", "msexchmailboxguid",
                                           "msexchmailboxsecuritydescriptor", "protocolsettings");

    /**
     * @param Coe_Ldap_Connection $conn
     * @throws Exception
     */
    public function __construct(Coe_Ldap_Connection $conn)
    {
        $this->conn = $conn;
        if (! $this->conn->isBound()) {
            throw new Exception('LDAP connection must be bound');
        }
    }

    /**
     * @return Coe_Ldap_Connection
     */
    public function getConnection()
    {
        return $this->conn;
    }

    /**
     * @param string $search
     * @param string $field
     * @param array $attributes
     * @return bool|Coe_Ldap_Result
     */
    public function getUserResult($search, $field = null, $attributes = array())
    {
        if (! $field) {
            $field = $this->glidKey;
        }
        $filter = "(|(" . $field . "=" . $this->conn->escape($search) . "))";
        return $this->conn->query($filter, $this->personsBaseDn, $attributes);
    }

    /**
     * @param string $glid
     * @param array $attributes
     * @return array
     */
    public function getAttributesByGlid($glid, $attributes = array())
    {
        $res = $this->getUserResult($glid, $this->glidKey, $attributes);
        return $res ? $this->processUserResult($res, true) : array();
    }

    /**
     * @param string $ufid
     * @param array $attributes
     * @return array
     */
    public function getAttributesByUfid($ufid, $attributes = array())
    {
        $res = $this->getUserResult($ufid, $this->ufidKey, $attributes);
        return $res ? $this->processUserResult($res, true) : array();
    }

    /**
     * @param string $glid
     * @param string $password
     * @param string $reason
     * @return bool
     */
    public function verifyPassword($glid, $password, &$reason = null)
    {
        $res = $this->getUserResult($glid, $this->glidKey, array(Coe_Ldap_Connection::FIELD_DN));
        if (! $res) {
            $reason = 'user not found';
            return false;
        } else {
            $dns = $this->getDistinguishedNames($res);
            if (! empty($dns[0]) && $this->conn->canBind($dns[0], $password)) {
                return true;
            }
        }
        $reason = 'password incorrect';
        return false;
    }

    /**
     * Fetch an array of users by querying on several attributes
     *
     * @param string $query
     * @param int $limit
     * @return array with each item an array of user attributes
     */
    public function findUsers($query, $limit = 50)
    {
        $query = $this->conn->escape($query);
        $filter = str_replace('%QUERY%', $query, $this->findUsersfilterFormat);
        $res = $this->conn->query($filter, $this->personsBaseDn, $this->findUsersReturnedAttributes, $limit);
        return $res ? $this->processUserResult($res) : array();
    }

    /**
     * @param string $groupCn e.g. THE-GROUP-NAME or CN=THE-GROUP-NAME,OU=...,DC=...
     * @param array $attrs
     * @return bool
     */
    public function isMemberOf($groupCn, array $attrs)
    {
        return Coe_Ldap::inGroup($groupCn, $attrs);
    }

    /**
     * @param Coe_Ldap_Result $res
     * @param bool $single
     * @return array
     */
    public function processUserResult(Coe_Ldap_Result $res, $single = false)
    {
        if (! $res->getLength()) {
            return array();
        }
        $entries = $res->getRawEntries();
        for ($i = 0; $i < $entries['count']; $i++) {
            $entries[$i] = $res->cleanUpEntries($entries[$i]);
            $entries[$i] = $this->processUserAttributes($entries[$i]);
        }
        unset($entries['count']);
        $entries = array_values($entries);
        return $single ? $entries[0] : $entries;
    }

    /**
     * @param Coe_Ldap_Result $res
     * @return array
     */
    public function getDistinguishedNames(Coe_Ldap_Result $res)
    {
        $entries = $res->getRawEntries();
        $dns = array();
        for ($i = 0; $i < $entries['count']; $i++) {
            if (! empty($entries[$i][$this->dnKey][0])) {
                $dns[] = $entries[$i][$this->dnKey][0];
            } else {
                $dns[] = null;
            }
        }
        return $dns;
    }

    /**
     * @param array $attributes
     * @return array
     */
    protected function processUserAttributes(array $attributes)
    {
        foreach ($this->userAttributesToRemove as $key) {
            unset($attributes[$key]);
        }

        $attributes['__fullname'] = $this->getFirstLast($attributes);
        if (! empty($attributes[$this->glidKey])) {
            $attributes['__glid'] = $attributes[$this->glidKey];
        }
        if (! empty($attributes[$this->ufidKey])) {
            $attributes['__ufid'] = $attributes[$this->ufidKey];
        }
        if (! empty($attributes[Coe_Ldap_Connection::FIELD_DN])
                && false !== strpos($attributes[Coe_Ldap_Connection::FIELD_DN], ',OU=Disabled Accounts,')) {
            $attributes['__disabled'] = '1';
        } else {
            $attributes['__disabled'] = '';
        }
        return $attributes;
    }

    /**
     * Compute a "first last" name from user attributes 'displayname' or 'givenname' and 'sn'
     *
     * @param array $attributes
     * @return string
     */
    public function getFirstLast(array $attributes)
    {
        if (! empty($attributes['displayname'])) {
            if (false === strpos($attributes['displayname'], ',')) {
                // no comma
                return $attributes['displayname'];
            }
            // has comma
            list($last, $first) = explode(',', $attributes['displayname'], 2);
        } else {
            $first = empty($attributes['givenname']) ? '' : $attributes['givenname'];
            $last = empty($attributes['sn']) ? '' : $attributes['sn'];
        }
        return trim($first) . ' ' . trim($last);
    }

    /**
     * @param array $config array with keys:
     *   server : default "ldaps://ldap.ad.ufl.edu"
     *   port : default 636
     *   rdn : (R)DN of user to authenticate, default null
     *   password : of user to authenticate, default null
     *   anonymousFallback : automatically bind anonymously if credentials fail, default false
     *
     * @return bool|Coe_Ldap_Ufad
     */
    static public function factory(array $config = array())
    {
        $config = array_merge(array(
            'server' => 'ldaps://ldap.ad.ufl.edu',
            'port' => '636',
        ), $config);
        $ldap = new Coe_Ldap($config);
        $conn = $ldap->getConnection();
        return $conn ? new self($conn) : false;
    }
}
