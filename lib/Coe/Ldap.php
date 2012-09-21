<?php

/**
 * Manages setting up a connection and binding to a service account
 */
class Coe_Ldap
{
    /**
     * @var array
     */
    protected $errors = array();

    /**
     * @var array
     */
    protected $config = array();

    /**
     * @var null|Coe_Ldap_Connection
     */
    protected $boundConnection = null;

    /**
     * @param array $config array with keys:
     *   server : ldaps?://hostname/
     *   port : default 389
     *   rdn : (R)DN of user to authenticate, default null
     *   password : of user to authenticate, default null
     *   anonymousFallback : automatically bind anonymously if credentials fail, default false
     */
    public function __construct(array $config = array())
    {
        $this->config = array_merge($this->getDefaults(), $config);
    }

    /**
     * @return array
     */
    public function getDefaults()
    {
        return array(
            'server' => '',
            'port' => 389,
            'rdn' => null,
            'password' => null,
            'anonymousFallback' => false,
        );
    }

    /**
     * @return array of string messages
     */
    public function getErrors()
    {
        return $this->errors;
    }

    /**
     * @param string $msg
     */
    public function addError($msg)
    {
        $this->errors[] = $msg;
    }

    /**
     * @return bool|Coe_Ldap_Connection
     */
    public function getConnection()
    {
        if (null === $this->boundConnection) {
            $c = $this->config;
            $this->boundConnection = $this->createBoundConnection($c['server'], $c['port'], $c['rdn'],
                                                                  $c['password'], $c['anonymousFallback']);
        }
        return $this->boundConnection;
    }

    /**
     * @param string $server
     * @param int $port
     * @param string|null $bindRdn
     * @param string|null $bindPassword
     * @param bool $anonymousFallback
     * @return bool|Coe_Ldap_Connection
     */
    public function createBoundConnection($server, $port = 389, $bindRdn = null,
                                          $bindPassword = null, $anonymousFallback = false)
    {
        try {
            $conn = new Coe_Ldap_Connection($server, $port);
        } catch (Exception $e) {
            $this->errors[] = $e->getMessage();
            return false;
        }
        if ($conn->bind($bindRdn, $bindPassword)) {
            return $conn;
        }
        if ($bindRdn && $anonymousFallback && $conn->bind()) {
            return $conn;
        }
        if ($bindRdn) {
            $this->errors[] = "Could not bind to user $bindRdn on $server";
        } else {
            $this->errors[] = "Could not bind anonymously on $server";
        }
        return false;
    }

    /**
     * @param string $groupCn e.g. THE-GROUP-NAME or CN=THE-GROUP-NAME,OU=...,DC=...
     * @param array $attrs
     * @return bool
     */
    static public function inGroup($groupCn, array $attrs)
    {
        if (empty($attrs['memberof'])) {
            return false;
        }
        $groupCn = self::normalizeCn($groupCn);
        if (0 !== strpos($groupCn, 'CN=')) {
            $groupCn = "CN=$groupCn";
        }
        if (false === strpos($groupCn, ',')) {
            $groupCn .= ',';
        }
        foreach ($attrs['memberof'] as $cn) {
            if (0 === strpos($cn, $groupCn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $cn
     * @return string
     */
    static public function normalizeCn($cn)
    {
        $cn = trim($cn);
        $cn = preg_replace('~\\s*,\\s*~', ',', $cn);
        $cn = preg_replace_callback('~(cn|ou|dc)=~', "Coe_Ldap::_cb1", $cn);
        return $cn;
    }

    static protected function _cb1($m)
    {
        return strtoupper($m[1]) . '=';
    }
}
