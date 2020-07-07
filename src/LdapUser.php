<?php

namespace gozoro\ldap;



/**
 * Ldap user read only.
 *
 * @author gozoro <gozoro@yandex.ru>
 */
class LdapUser extends LdapObject
{
	/**
	 * If this userAccountControl bit is set, the regarding user account is disabled and
	 * cannot authenticate to the domain any more. Please do not confuse this with the Intruder
	 * Lockout mechanism which locks out a user if he enter a wrong password to often in too short a time.
	 */
	const UF_ACCOUNTDISABLE = 2;

	/**
	 * This userAccountControl bit indicates that this is a normal user account.
	 * To distinguish this type of account from other types is necessary because not only user objects
	 * have a userAccountControl attribute, but also computer objects and others representing domain
	 * controllers or trust relationships.
	 */
	const UF_NORMAL_ACCOUNT = 512;

	/**
	 * If this userAccountControl bit is set, the user is not subject to an existing policy regarding
	 * a forced password change interval: The password of this account never expires.
	 */
	const UF_DONT_EXPIRE_PASSWD = 65536;



	/**
	 * Returns default ldap-attributes for the found user.
	 *
	 * @return array
	 */
	static public function defaultAttributes()
	{
		return array('samaccountname', 'userPrincipalName',
			'objectCategory', 'objectClass', 'objectSID', 'objectGUID',
			'name', 'givenName', 'sn', 'displayName', 'description', 'mailNickname',
			'mail', 'telephoneNumber', 'homephone', 'mobile', 'pager',
			'company', 'department', 'title',
			'whenchanged', 'whencreated', 'badpasswordtime',
			'pwdlastset', 'badpwdcount', 'lastlogontimestamp', 'UserAccountControl',
			'cn', 'accountExpires', 'memberOf'
			);
	}

	public function __toString()
	{
		return $this->getPrincipalName();
	}

	/**
	 * Returns user logon name without domain name.
	 * Alias of method getSamAccountName().
	 *
	 * @return string|NULL
	 */
	public function getUsername()
	{
		return $this->getSamAccountName();
	}

	/**
	 * Returns user logon name (pre-Windows 2000), e.g. mydomain\john.
	 *
	 * @return string|NULL
	 */
	public function getUsernamePreWindows2000()
	{
		$parts = explode('.', $this->getDomainName());
		$suffix = $parts[0];

		$username = $this->getSamAccountName();

		return $suffix."\\".$username;
	}

	/**
	 * Returns user logon name. e.g. john@mydomain.net.
	 *
	 * @return string|NULL
	 */
	public function getPrincipalName()
	{
		$domain   = $this->getDomainName();
		$username = $this->getSamAccountName();

		if($username)
			return $username.'@'.$domain;
		else
			return null;
	}

	/**
	 * Returns TRUE if user account is disabled.
	 *
	 * @return bool
	 */
	public function isDisabled()
	{
		$accessFlags = $this->getLdapAttribute('useraccountcontrol');
		return (bool)($accessFlags & self::UF_ACCOUNTDISABLE);
	}

	/**
	 * Returns TRUE if user account is enabled.
	 *
	 * @return bool
	 */
	public function isEnabled()
	{
		return !$this->isDisabled();
	}

	/**
	 * Returns TRUE if this object is a normal user account.
	 *
	 * @return bool
	 */
	public function isNormalAccount()
	{
		$accessFlags = $this->getLdapAttribute('useraccountcontrol');
		return (bool)($accessFlags & self::UF_NORMAL_ACCOUNT);
	}

	/**
	 * Returns first name of user.
	 *
	 * @return string|NULL
	 */
	public function getFirstName()
	{
		return $this->getLdapAttribute('givenName');
	}

	/**
	 * Returns last name of user.
	 *
	 * @return string|NULL
	 */
	public function getLastName()
	{
		return $this->getLdapAttribute('sn');
	}

	/**
	 * Returns display name of user.
	 *
	 * @return string|NULL
	 */
	public function getDisplayName()
	{
		return $this->getLdapAttribute('displayName');
	}

	/**
	 * Returns email of user.
	 *
	 * @return string|NULL
	 */
	public function getEmail()
	{
		return $this->getLdapAttribute('mail');
	}

	/**
	 * Returns email nickname.
	 *
	 * @return string|NULL
	 */
	public function getEmailNickName()
	{
		return $this->getLdapAttribute('mailNickname');
	}

	/**
	 * Returns telephone nubmer.
	 *
	 * @return string|NULL
	 */
	public function getPhone()
	{
		return $this->getLdapAttribute('telephoneNumber');
	}

	/**
	 * Returns mobile phone number.
	 *
	 * @return string|NULL
	 */
	public function getMobilePhone()
	{
		return $this->getLdapAttribute('mobile');
	}

	/**
	 * Returns home telephone number.
	 *
	 * @return string|NULL
	 */
	public function getHomePhone()
	{
		return $this->getLdapAttribute('homephone');
	}

	/**
	 * Returns a pager number.
	 *
	 * @return string|NULL
	 */
	public function getPager()
	{
		return $this->getLdapAttribute('pager');
	}

	/**
	 * Returns a company name of user.
	 *
	 * @return string|NULL
	 */
	public function getCompany()
	{
		return $this->getLdapAttribute('company');
	}

	/**
	 * Returns a department name of user.
	 *
	 * @return string|NULL
	 */
	public function getDepartment()
	{
		return $this->getLdapAttribute('department');
	}

	/**
	 * Returns a title of user.
	 *
	 * @return string|NULL
	 */
	public function getTitle()
	{
		return $this->getLdapAttribute('title');
	}

	/**
	 * Returns a office of user.
	 *
	 * @return string|NULL
	 */
	public function getOffice()
	{
		return $this->getLdapAttribute('physicalDeliveryOfficeName');
	}

	/**
	 * Returns the date and time of the last bad login.
	 *
	 * @param string $format date format
	 * @return string|NULL
	 */
	public function getBadPasswordTime($format = 'Y-m-d H:i:s')
	{
		$time = $this->getLdapAttribute('badpasswordtime');
		if($time)
			return Ldap::convertLdapTimestampToDate($time, $format);
		else
			return null;
	}

	/**
	 * Returns the count of bad login attempts.
	 *
	 * @return int
	 */
	public function getBadPasswordCount()
	{
		return (int)$this->getLdapAttribute('badpwdcount');
	}

	/**
	 * Returns the date and time when the password was last set for this account.
	 *
	 * @param string $format date format
	 * @return string|NULL
	 */
	public function getLastSetPasswordTime($format = 'Y-m-d H:i:s')
	{
		$time = $this->getLdapAttribute('pwdlastset');
		if($time)
			return Ldap::convertLdapTimestampToDate( $time, $format );
		else
			return null;
	}

	/**
	 * Returns the date and time of the last successful login.
	 *
	 * @param string $format date format
	 * @return string|NULL
	 */
	public function getLastLogonTime($format = 'Y-m-d H:i:s')
	{
		$time = $this->getLdapAttribute('lastlogontimestamp');
		if($time)
			return Ldap::convertLdapTimestampToDate( $time, $format );
		else
			return null;
	}

	/**
	 * Returns TRUE when the user account has a expire time set.
	 * @return bool
	 */
	public function hasAccountExpires()
	{
		$accessFlags = $this->getLdapAttribute('useraccountcontrol');
		return ! (bool)($accessFlags & self::UF_DONT_EXPIRE_PASSWD);
	}

	/**
	 * Returns the date and time while the account is active.
	 * Returns NULL if rhe password of this account never expires.
	 *
	 * @param string $format date format
	 * @return string|NULL
	 */
	public function getAccountExpires($format = 'Y-m-d H:i:s')
	{
		if($this->hasAccountExpires())
		{
			$accountExpiries = $this->getLdapAttribute('accountExpires');

			if($accountExpiries)
				return Ldap::convertLdapTimestampToDate( $accountExpiries, $format );
			else
				return null;
		}
		else
		{
			return null;
		}
	}

	/**
	 * Returns array of Organizational Units.
	 *
	 * @return array
	 */
	public function getOrganizationalUnits()
	{
		$parts = explode(',', $this->getDN());
		$units = [];

		for($i=count($parts)-1; $i>=0; $i--)
		{
			$key_value = $parts[$i];
			list($key, $value) = explode('=', $key_value);
			if(strtoupper($key) == 'OU')
			{
				$units[] = $value;
			}
		}

		return $units;
	}

	/**
	 * Returns an array of groups that the user belongs to.
	 *
	 * @return array of LdapGroup
	 */
	public function getGroups()
	{
		$dn = $this->getDN();

		$ldapGroups = $this->ldap()->search('(&(objectClass=group)(member='.$dn.'))', LdapGroup::defaultAttributes());

		$groups = [];
		if($ldapGroups)
			foreach($ldapGroups as $groupAttributes)
			{
				$groups[] = new LdapGroup($this->ldap(), $groupAttributes);
			}

		return $groups;
	}


	/**
	 * Returns an array of group names that the user belongs to.
	 *
	 * @return array of string
	 */
	public function getGroupNames()
	{
		$groupNames = [];
		foreach($this->getGroups() as $group) /* @var $group LdapGroup  */
		{
			$groupNames[] = $group->getSamAccountName();
		}
		return $groupNames;
	}

	/**
	 * Validate password. Returns TRUE if the password allows authentication.
	 *
	 * @param string $password
	 * @return boolean
	 */
	public function validatePassword($password)
	{
		$principalName = $this->getPrincipalName();
		return $this->ldap()->validatePassword($principalName, $password);
	}
}