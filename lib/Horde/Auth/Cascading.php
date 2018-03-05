<?php
/**
 * Copyright 2017-2018 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (LGPL). If you did
 * not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Florian Frank <frank@b1-systems.de> (implementation)
 * @author   Ralf Lang <lang@b1-systems.de> (concept)
 * @category Horde
 * @license http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @package  Auth
 */

/**
 * The Horde_Auth_Cascading class provides a way to combine multiple
 * authentication drivers for local overrides and integration scenarios
 *
 * @author   Florian Frank <frank@b1-systems.de> (implementation)
 * @author   Ralf Lang <lang@b1-systems.de> (concept)
 * @category  Horde
 * @copyright 2017-2018 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @package   Auth
 */
class Horde_Auth_Cascading extends Horde_Auth_Base
{
    /**
     * Constructor.
     *
     * @param array $params  Required parameters:
     * <pre>
     * 'drivers' - array hash of (Horde_Auth_Base) The list of backend drivers.
     * 'capabilities' - defines capabilities this driver
     *   exposes and how to map them to the backends.
     *   Defaults to "order" for all drivers which support it.
     * </pre>
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $params = array())
    {
        if (!isset($params['drivers'])) {
            throw new InvalidArgumentException('Missing ' . $params['drivers'] . ' parameter.');
        }
        $capabilities = array();
        foreach ($this->_capabilities as $capabilityKey => $capability) {
            foreach ($params['drivers'] as $driverKey => $driver) {
                if ($params['drivers'][$driverKey]->hasCapability($capabilityKey)) {
                    if (empty($capabilities[$capabilityKey])) {
                        $capabilities[$capabilityKey] = array();
                    }
                    array_push($capabilities[$capabilityKey], $driverKey);
                }
            }
        }
        if (!empty($params['capabilities'])) { 
            // override default capabilities with provided capabilities
            $capabilities = array_merge($capabilities, $params['capabilities']);
        } 
        $params['capabilities'] = $capabilities;
        parent::__construct($params);
    }

    /**
     * Find out if a set of login credentials are valid.
     * Valid means valid in any backend
     *
     * @param string $userId      The userId to check.
     * @param array $credentials  The credentials to use.
     *
     * @throws Horde_Auth_Exception
     */
    protected function _authenticate($userId, $credentials)
    {
        // Return if any driver accepts this userId and credentials as valid
        foreach ($this->_params['capabilities']['authenticate'] as $driverKey) {
            if ($this->_params['drivers'][$driverKey]->authenticate($userId, $credentials)) {
                return;
            }
        }
        // Otherwise throw an exception
        throw new Horde_Auth_Exception('', Horde_Auth::REASON_BADLOGIN);
    }

    /**
     * Advertise capability if a capability has backend driver
     *
     * @param string $capability  The capability to test for.
     *
     * @return boolean  Whether or not the capability is supported.
     */
    public function hasCapability($capability)
    {
        if (empty($this->_params['capabilities'][$capability])) {
            return false;
        }
        return true;
    }

    /**
     * Automatic authentication.
     *
     * @return boolean  Whether or not the client is allowed.
     */
    public function transparent()
    {
        if (!$this->hasCapability('transparent'))
        {
            throw new Horde_Auth_Exception('Unsupported.');
        }   
        foreach ($this->_params['capabilities']['transparent'] as $driverKey) {
            try{
                if ($this->_params['drivers']['driverKey']->transparent()) {
                    return true;
                }             
            }catch (Horde_Auth_Exception $e){
            }
        }
        return false;
    }

    /**
     * Add a set of authentication credentials.
     *
     * @param string $userId       The userId to add.
     * @param array  $credentials  The credentials to use.
     *
     * @throws Horde_Auth_Exception
     */
    public function addUser($userId, $credentials)
    {
        // TODO try to add the user to all backends in $this->_params['capabilities']['add'] - throw exception if no driver available
        if (!$this->hasCapability('add')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        foreach ($this->_params['capabilities']['add'] as $driverKey) {
            try{
                $this->_params['drivers'][$driverKey]->addUser($userId, $credentials);    
            }catch (Horde_Auth_Exception $e) {
            }
        }
    }
/**
     * Update a set of authentication credentials.
     *
     * @param string $oldID       The old userId.
     * @param string $newID       The new userId.
     * @param array $credentials  The new credentials
     *
     * @throws Horde_Auth_Exception
     */
    public function updateUser($oldID, $newID, $credentials)
    {
        // TODO try to add the user to all backends in $this->_params['capabilities']['update'] - throw exception if no driver available
        if (!$this->hasCapability('update')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        foreach ($this->_params['capabilities']['update'] as $driverKey) {
            try{
                $this->_params['drivers'][$driverKey]->updateUser($oldID, $newID, $credentials);
            }  catch (Horde_Auth_Exception $e) {
            }
        }
    }

    /**
     * Reset a user's password. Used for example when the user does not
     * remember the existing password.
     *
     * @param string $userId  The user id for which to reset the password.
     *
     * @return string  The new password on success.
     * @throws Horde_Auth_Exception
     */
    public function resetPassword($userId)
    {
        if (!$this->hasCapability('resetpassword')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        $newPassword = '';
        $resetButUpdate = array();
        foreach ($this->_params['capabilities']['resetpassword'] as $resetKey) {
            if (in_array($resetKey, $this->_params['capabilities']['update'])) {
                    array_push($resetButUpdate, $resetKey);
            } else {
                try {
                    $newPassword = $this->_params['drivers'][$resetKey]->resetPassword($userId);
                } catch (Horde_Auth_Exception $e) {
                }
            }
        }

        if (!empty($resetButUpdate)) {
            if ($newPassword == '') {
                $newPassword = Horde_Auth::genRandomPassword();
            }
            $credentials = array('password' => $newPassword);
            foreach ($resetButUpdate as $driverKey) {
                try{
                    $this->_params['drivers'][$driverKey]->updateUser($userId, $userId, $credentials);
                } catch (Horde_Auth_Exception $e) {
                }
            }
        }
        return $newPassword;
    }

    /**
     * Delete a set of authentication credentials.
     *
     * @param string $userId  The userId to delete.
     *
     * @throws Horde_Auth_Exception
     */
    public function removeUser($userId)
    {
        if (!$this->hasCapability('remove')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        $users = array();
        foreach ($this->_params['capabilities']['remove'] as $driverKey) {
            try{
                $this->_params['drivers'][$driverKey]->removeUser($userId);
            }  catch (Horde_Auth_Exception $e) {
            }
        }
    }

    /**
     * Lists all users in the system.
     *
     * @param boolean $sort  Sort the users?
     *
     * @return array  The array of userIds.
     * @throws Horde_Auth_Exception
     */
    public function listUsers($sort = false)
    {
        if (!$this->hasCapability('list')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        $users = array();
        foreach ($this->_params['capabilities']['list'] as $driverKey) {
            try {
                $users = array_merge($users , $this->_params['drivers'][$driverKey]->listUsers($sort)); 
            } catch (Horde_Auth_Exception $e) {
            }
        }
        $uniqueUsers = array_values(array_unique($users));
        return($uniqueUsers);
    }

    /**
     * Checks if a userId exists in the system.
     *
     * @param string $userId  User ID to check
     *
     * @return boolean  Whether or not the userId already exists.
    */ 
    public function exists($userId)
    {
        if (!$this->hasCapability('list') && !$this->hasCapability('exists')) {
            throw new Horde_Auth_Exception('Unsupported.');
        }
        if ($this->hasCapability('exists')) {
            foreach ($this->_params['capabilities']['exists'] as $existsKey) {
                try {
                    if ($this->_params['drivers'][$existsKey]->exists($userId)) {
                        return true;
                    }
                } catch (Horde_Auth_Exception $e) {
                }
            }
        }
        foreach ($this->_params['capabilities']['list'] as $listKey) {
            try {
                if (in_array($userId, $this->_params['drivers'][$listKey]->listUsers())) {
                    return true;
                }
            } catch (Horde_Auth_Exception $e) {
            }
        }
        return false;
    }
}
