<?php

namespace gozoro\ldap;




/**
 * Ldap group. Read only.
 *
 * @author gozoro <gozoro@yandex.ru>
 */
class LdapGroup extends LdapObject
{
	/**
	 * Returns default ldap-attributes for the found group.
	 * 
	 * @return array
	 */
	static public function defaultAttributes()
	{
		return array('samaccountname', 'objectCategory', 'objectClass', 'objectSID', 'objectGUID',
			'name', 'description', 'whenchanged', 'whencreated', 'cn'
			);
	}

	public function __toString()
	{
		return $this->getName();
	}

	/**
	 * Returns subgroups (members of group).
	 *
	 * @return array of LdapGroup
	 */
	public function getGroups()
	{
		$dn = $this->getDN();

		$ldapGroups = $this->ldap()->search('(&(objectClass=group)(memberOf='.$dn.'))', LdapGroup::defaultAttributes());

		$groups = [];
		if($ldapGroups)
			foreach($ldapGroups as $groupAttributes)
			{
				$groups[] = new LdapGroup($this->ldap(), $groupAttributes);
			}

		return $groups;
	}

	/**
	 * Returns users (members of group).
	 *
	 * @return array of LdapUser
	 */
	public function getUsers()
	{
		$dn = $this->getDN();

		$ldapUsers = $this->ldap()->search('(&(objectClass=user)(memberOf='.$dn.'))', LdapUser::defaultAttributes());

		$users = [];
		if($ldapUsers)
			foreach($ldapUsers as $userAttributes)
			{
				$users[] = new LdapUser($this->ldap(), $userAttributes);
			}

		return $users;
	}
}