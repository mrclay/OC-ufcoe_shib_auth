<?php

class Coe_Ldap_Result
{
    protected $link;

    protected $result;

    protected $entries = null;

    /**
     * @param resource $link
     * @param resource $result
     */
    public function __construct($link, $result)
    {
        $this->link = $link;
        $this->result = $result;
    }

    /**
     * @return int
     */
    public function getLength()
    {
        return (int) ldap_count_entries($this->link, $this->result);
    }

    /**
     * @return array|bool
     */
    public function getRawEntries()
    {
        if (null === $this->entries) {
            $this->entries = @ldap_get_entries($this->link, $this->result);
        }
        return $this->entries;
    }

    /**
     * @param bool $single
     * @return array
     */
    public function getArray($single = false)
    {
        if (! ($entries = $this->getRawEntries())) {
            return array();
        }
        $entries = $this->cleanUpEntries($entries);
        if ($single) {
            list(, $entries) = each($entries);
        }
        return $entries;
    }

    /**
     * @param array $entries
     * @return array
     * @link http://www.php.net/manual/en/function.ldap-get-entries.php#89508
     */
    public function cleanUpEntries(array $entries)
    {
        $retEntry = array();
        for ($i = 0; $i < $entries['count']; $i++) {
            if (is_array($entries[$i])) {
                $subtree = $entries[$i];
                // This condition should be superfluous so just take the recursive call
                // adapted to your situation in order to increase perf.
                if (! empty($subtree['dn']) and ! isset($retEntry[$subtree['dn']])) {
                    $retEntry[$subtree['dn']] = $this->cleanUpEntries($subtree);
                } else {
                    $retEntry[] = $this->cleanUpEntries($subtree);
                }
            } else {
                $attribute = $entries[$i];
                if ($entries[$attribute]['count'] == 1) {
                    $retEntry[$attribute] = $entries[$attribute][0];
                } else {
                    for ($j = 0; $j < $entries[$attribute]['count']; $j++) {
                        $retEntry[$attribute][] = $entries[$attribute][$j];
                    }
                }
            }
        }
        return $retEntry;
    }
}