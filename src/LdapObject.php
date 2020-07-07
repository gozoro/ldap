<?php

namespace gozoro\ldap;




/**
 * Ldap object abstract model.
 *
 * @author gozoro <gozoro@yandex.ru>
 */
abstract class LdapObject
{
	/**
	 * Link to Ldap
	 * @var Ldap;
	 */
	private $_ldap;

	/**
	 * Attributes
	 * @var array
	 */
	private $_attributes;



	/**
	 * Abstract constructor.
	 *
	 * @param Ldap $ldap
	 * @param array $ldapAttributes
	 */
	public function __construct(Ldap $ldap, array $ldapAttributes)
	{
		$this->_ldap       = $ldap;
		$this->_attributes = $ldapAttributes;
	}

	/**
	 * Returns link to Ldap object.
	 *
	 * @return Ldap
	 */
	protected function ldap()
	{
		return $this->_ldap;
	}


	/**
	 * Default ldap attributes.
	 *
	 * @return array
	 */
	abstract public static function defaultAttributes();


	/**
	 * Returns domain name of ldap object.
	 *
	 * @return string
	 */
	public function getDomainName()
	{
		return $this->ldap()->getDomainName();
	}

	/**
	 * Returns value of ldap-attribute.
	 *
	 * @param string $attribute
	 * @return string|NULL
	 */
	public function getLdapAttribute($attribute)
	{
		$attribute = strtolower(trim($attribute));

		if(is_array($this->_attributes) and array_key_exists($attribute, $this->_attributes))
		{
			return $this->_attributes[$attribute];
		}
		else
			return null;
	}

	/**
	 * Returns distinguished name.
	 *
	 * @return string
	 */
	public function getDN()
	{
		return $this->getLdapAttribute('dn');
	}

	/**
	 * Returns value of ldap-attribute "samaccountname".
	 * User logon name without domain name.
	 *
	 * @return string
	 */
	public function getSamAccountName()
	{
		return $this->getLdapAttribute('samaccountname');
	}

	/**
	 * Returns SID (ldap-attribute "objectSID") as binary data.
	 *
	 * @return string
	 */
	public function getObjectSIDBinary()
	{
		return $this->getLdapAttribute('objectSID');
	}

	/**
	 * Returns SID (ldap-attribute "objectSID") as string.
	 *
	 * @return string
	 */
	public function getObjectSID()
	{
		return Ldap::convertObjectSIDBinayToString( $this->getObjectSIDBinary() );
	}

	/**
	 * Returns GUID (ldap-attribute "objectGUID") as binary data.
	 *
	 * @return string
	 */
	public function getObjectGUIDBinary()
	{
		return $this->getLdapAttribute('objectGUID');
	}

	/**
	 * Returns GUID (ldap-attribute "objectGUID") as string.
	 *
	 * @return string
	 */
	public function getObjectGUID()
	{
		return Ldap::convertObjectGUIDBinaryToString( $this->getObjectGUIDBinary() );
	}


	/**
	 * Returns an array of object classes.
	 *
	 * @return array
	 */
	public function getObjectClass()
	{
		return (array)$this->getLdapAttribute('objectClass');
	}

	/**
	 * Returns the category. For example: "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com".
	 *
	 * @return string
	 */
	public function getObjectCategory()
	{
		return $this->getLdapAttribute('objectCategory');
	}

	/**
	 * Returns the full name.
	 *
	 * @return string
	 */
	public function getName()
	{
		return $this->getLdapAttribute('name');
	}

	/**
	 * Returns the description.
	 *
	 * @return string
	 */
	public function getDescription()
	{
		return $this->getLdapAttribute('description');
	}


	/**
	 * Returns the common name (lastName + firstName).
	 *
	 * @return string
	 */
	public function getCommonName()
	{
		return $this->getLdapAttribute('cn');
	}

	/**
	 * Returns the creation date and time.
	 *
	 * @param string $format date format
	 * @return string
	 */
	public function getWhenCreated($format = 'Y-m-d H:i:s')
	{
		return Ldap::convertYYYYMMDDHHmmssToDate( $this->getLdapAttribute('whencreated'), $format);
	}

	/**
	 * Returns the date and time of last change.
	 *
	 * @param string $format date format
	 * @return string
	 */
	public function getWhenChanged($format = 'Y-m-d H:i:s')
	{
		return Ldap::convertYYYYMMDDHHmmssToDate( $this->getLdapAttribute('whenchanged'), $format );
	}
}