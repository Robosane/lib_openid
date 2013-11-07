<?php
/**
 * @version     1.0.0
 * @package     mod_steamlogin
 * @copyright   Copyright (C) 2013. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      DZ Team <dev@dezign.vn> - dezign.vn
 */

// no direct access
defined( '_JEXEC' ) or die( 'Restricted access' );

/**
* @access private
*/
require_once 'Auth/OpenID/Interface.php';
require_once 'Auth/OpenID/Nonce.php';

/**
* @access private
*/
require_once 'Auth/OpenID.php';

/**
* @access private
*/
require_once 'Auth/OpenID/Nonce.php';

class Auth_OpenID_JDatabaseStore extends Auth_OpenID_OpenIDStore {
    /*
     * @var JDatabaseObject
     */
    private $_dbo;

    /*
     * @var mysqli
     */
    private $_connection;

    /*
     * @var string
     */
    private $_prefix;

    /*
     * @var string
     */
    private $_associations_table_name;
    private $_nonces_table_name;

    public function __construct()
    {
        $this->_dbo = &JFactory::getDBO();
        $this->_connection = &$this->_dbo->getConnection();

        $this->_prefix = $this->_dbo->getPrefix();
        $this->_associations_table_name = $this->_prefix . 'oid_associations';
        $this->_nonces_table_name = $this->_prefix . 'oid_nonces';
    }

    public function tableExists($table_name)
    {
        $tables = $this->_dbo->getTableList();

        return in_array($table_name, $tables);
    }

    function createTables()
    {
        $n = $this->create_nonce_table();
        $a = $this->create_assoc_table();

        if ($n && $a) {
            return true;
        } else {
            return false;
        }
    }

    function create_nonce_table()
    {
        if (!$this->tableExists($this->_associations_table_name)) {
            $query = "CREATE TABLE IF NOT EXISTS #__oid_nonces(server_url VARCHAR(2047) NOT NULL, timestamp INTEGER NOT NULL, salt CHAR(40) NOT NULL, UNIQUE (server_url(255), timestamp, salt));";
            $this->_dbo->setQuery($query);
            try {
                $this->_dbo->execute();
            } catch (Exception $e) {
                return false;
            }
        }
        return true;
    }

    function create_assoc_table()
    {
        if (!$this->tableExists($this->_associations_table_name)) {
            $query = "CREATE TABLE IF NOT EXISTS #__oid_associations(server_url VARCHAR(2047) NOT NULL, handle VARCHAR(255) NOT NULL, secret BLOB NOT NULL, issued INTEGER NOT NULL, lifetime INTEGER NOT NULL, assoc_type VARCHAR(64) NOT NULL, PRIMARY KEY (server_url(255), handle));";
            $this->_dbo->setQuery($query);
            try {
                $this->_dbo->execute();
            } catch (Exception $e) {
                return false;
            }
        }
        return true;
    }

    /**
     * @access private
     */
    function blobEncode($blob)
    {
        return "0x" . bin2hex($blob);
    }

    function blobDecode($blob)
    {
        return $blob;
    }

    /**
     * This method puts an Association object into storage,
     * retrievable by server URL and handle.
     *
     * @param string $server_url The URL of the identity server that
     * this association is with. Because of the way the server portion
     * of the library uses this interface, don't assume there are any
     * limitations on the character set of the input string. In
     * particular, expect to see unescaped non-url-safe characters in
     * the server_url field.
     *
     * @param Association $association The Association to store.
     */
    function storeAssociation($server_url, $association)
    {
        try {
            $this->_dbo->transactionStart();

            $query = $this->_dbo->getQuery(true);
            $query->insert($this->_associations_table_name);
            $query->columns('server_url, handle, secret, issued,lifetime, assoc_type');
            $query->values("'" . $query->escape($server_url) . "', '" . $association->handle . "', '" . $this->blobEncode($association->secret) . "', '" . $association->issued . "', '" . $association->lifetime . "', '" . $association->assoc_type . "'");

            $query = str_replace('INSERT INTO', 'REPLACE INTO', (string) $query);
            $this->dbo->setQuery($query);
            $this->dbo->execute();

            $this->_dbo->transactionCommit();
        } catch (Exception $e) {
            $this->_dbo->transactionRollback();
        }
    }

    /*
     * Remove expired nonces from the store.
     *
     * Discards any nonce from storage that is old enough that its
     * timestamp would not pass useNonce().
     *
     * This method is not called in the normal operation of the
     * library.  It provides a way for store admins to keep their
     * storage from filling up with expired data.
     *
     * @return the number of nonces expired
     */
    function cleanupNonces()
    {
        global $Auth_OpenID_SKEW;
        $v = time() - $Auth_OpenID_SKEW;

        $query = $this->_dbo->getQuery(true);
        $query->delete($this->_nonces_table_name);
        $query->where('timestame < ' . $query->escape($v));

        $this->_dbo->setQuery($query);
        $this->_dbo->execute();
        $num = $this->_dbo->getAffectedRows();

        return $num;
    }

    /*
     * Remove expired associations from the store.
     *
     * This method is not called in the normal operation of the
     * library.  It provides a way for store admins to keep their
     * storage from filling up with expired data.
     *
     * @return the number of associations expired.
     */
    function cleanupAssociations()
    {
        global $Auth_OpenID_SKEW;
        $v = time() - $Auth_OpenID_SKEW;

        $query = $this->_dbo->getQuery(true);
        $query->delete($this->_associations_table_name);
        $query->where('issued + lifetime < ' . $query->escape($v));

        $this->_dbo->setQuery($query);
        $this->_dbo->execute();
        $num = $this->_dbo->getAffectedRows();

        return $num;
    }

    /*
     * Shortcut for cleanupNonces(), cleanupAssociations().
     *
     * This method is not called in the normal operation of the
     * library.  It provides a way for store admins to keep their
     * storage from filling up with expired data.
     */
    function cleanup()
    {
        return array($this->cleanupNonces(),
                     $this->cleanupAssociations());
    }

    /**
     * Report whether this storage supports cleanup
     */
    function supportsCleanup()
    {
        return true;
    }

    /**
     * This method returns an Association object from storage that
     * matches the server URL and, if specified, handle. It returns
     * null if no such association is found or if the matching
     * association is expired.
     *
     * If no handle is specified, the store may return any association
     * which matches the server URL. If multiple associations are
     * valid, the recommended return value for this method is the one
     * most recently issued.
     *
     * This method is allowed (and encouraged) to garbage collect
     * expired associations when found. This method must not return
     * expired associations.
     *
     * @param string $server_url The URL of the identity server to get
     * the association for. Because of the way the server portion of
     * the library uses this interface, don't assume there are any
     * limitations on the character set of the input string.  In
     * particular, expect to see unescaped non-url-safe characters in
     * the server_url field.
     *
     * @param mixed $handle This optional parameter is the handle of
     * the specific association to get. If no specific handle is
     * provided, any valid association matching the server URL is
     * returned.
     *
     * @return Association The Association for the given identity
     * server.
     */
    function getAssociation($server_url, $handle = null)
    {
        if ($handle !== null) {
            $assoc = $this->_get_assoc($server_url, $handle);

            $assocs = array();
            if ($assoc) {
                $assocs[] = $assoc;
            }
        } else {
            $assocs = $this->_get_assocs($server_url);
        }

        if (!$assocs || (count($assocs) == 0)) {
            return null;
        } else {
            $associations = array();

            foreach ($assocs as $assoc_row) {
                $assoc = new Auth_OpenID_Association($assoc_row['handle'],
                                                     $assoc_row['secret'],
                                                     $assoc_row['issued'],
                                                     $assoc_row['lifetime'],
                                                     $assoc_row['assoc_type']);

                $assoc->secret = $this->blobDecode($assoc->secret);

                if ($assoc->getExpiresIn() == 0) {
                    $this->removeAssociation($server_url, $assoc->handle);
                } else {
                    $associations[] = array($assoc->issued, $assoc);
                }
            }

            if ($associations) {
                $issued = array();
                $assocs = array();
                foreach ($associations as $key => $assoc) {
                    $issued[$key] = $assoc[0];
                    $assocs[$key] = $assoc[1];
                }

                array_multisort($issued, SORT_DESC, $assocs, SORT_DESC,
                                $associations);

                // return the most recently issued one.
                list($issued, $assoc) = $associations[0];
                return $assoc;
            } else {
                return null;
            }
        }
    }

    private function _get_assoc($server_url, $handle)
    {
        $query = $this->_dbo->getQuery(true);
        $query->select('handle, secret, issued, lifetime, assoc_type');
        $query->from($this->_associations_table_name);
        $query->where('server_url = \'' . $query->escape($server_url) . '\' AND handle = \'' . $query->escape($server_url) . '\'');

        $this->_dbo->setQuery($query);

        return $this->_dbo->loadAssoc();
    }

    private function _get_assocs($server_url)
    {
        $query = $this->_dbo->getQuery(true);
        $query->select('handle, secret, issued, lifetime, assoc_type');
        $query->from($this->_associations_table_name);
        $query->where('server_url = \'' . $query->escape($server_url) . '\'');

        $this->_dbo->setQuery($query);

        return $this->_dbo->loadAssocList();
    }

    /**
     * This method removes the matching association if it's found, and
     * returns whether the association was removed or not.
     *
     * @param string $server_url The URL of the identity server the
     * association to remove belongs to. Because of the way the server
     * portion of the library uses this interface, don't assume there
     * are any limitations on the character set of the input
     * string. In particular, expect to see unescaped non-url-safe
     * characters in the server_url field.
     *
     * @param string $handle This is the handle of the association to
     * remove. If there isn't an association found that matches both
     * the given URL and handle, then there was no matching handle
     * found.
     *
     * @return mixed Returns whether or not the given association existed.
     */
    function removeAssociation($server_url, $handle)
    {
        if ($this->_get_assoc($server_url, $handle) == null) {
            return false;
        }

        try {
            $this->_dbo->transactionStart();

            $query = $this->_dbo->getQuery(true);
            $query->delete($this->_associations_table_name);
            $query->where("server_url = '". $query->escape($server_url) . "' AND handle = '" . $query->escape($handle) . "'");
            $this->_dbo->setQuery($query);
            $this->_dbo->execute();

            $this->_dbo->transactionCommit();
        } catch (Exception $e) {
            $this->_dbo->transactionRollback();
        }

        return true;
    }

    /**
     * Called when using a nonce.
     *
     * This method should return C{True} if the nonce has not been
     * used before, and store it for a while to make sure nobody
     * tries to use the same value again.  If the nonce has already
     * been used, return C{False}.
     *
     * Change: In earlier versions, round-trip nonces were used and a
     * nonce was only valid if it had been previously stored with
     * storeNonce.  Version 2.0 uses one-way nonces, requiring a
     * different implementation here that does not depend on a
     * storeNonce call.  (storeNonce is no longer part of the
     * interface.
     *
     * @param string $nonce The nonce to use.
     *
     * @return bool Whether or not the nonce was valid.
     */
    function useNonce($server_url, $timestamp, $salt)
    {
        global $Auth_OpenID_SKEW;

        if ( abs($timestamp - time()) > $Auth_OpenID_SKEW ) {
            return false;
        }

        return $this->_add_nonce($server_url, $timestamp, $salt);
    }

    private function _add_nonce($server_url, $timestamp, $salt)
    {
        try {
            $this->_dbo->transactionStart();

            $query = $this->_dbo->getQuery(true);
            $query->insert($this->_nonces_table_name);
            $query->columns('server_url, timestamp, salt');
            $query->values("'" . $query->escape($server_url) . "', '" . $query->escape($timestamp) . "', '" . $query->escape($salt) . "'");

            $this->_dbo->setQuery($query);
            $result = $this->_dbo->execute();

            $this->_dbo->transactionCommit();
        } catch (Exception $e) {
            $this->_dbo->transactionRollback();
            return false;
        }

        return true;
    }

    /**
     * Removes all entries from the store; implementation is optional.
     */
    function reset()
    {
        try {
            $query = $this->_dbo->getQuery(true);
            $query->delete($this->_associations_table_name);
            $this->_dbo->setQuery($query);
            $this->_dbo->execute();

            $query = $this->_dbo->getQuery(true);
            $query->delete($this->_nonces_table_name);
            $this->_dbo->setQuery($query);
            $this->_dbo->execute();
        } catch (Exception $e) {
            return false;
        }

        return true;
    }
}