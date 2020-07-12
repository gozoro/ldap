<?php

namespace gozoro\ldap;


/**
 * LDAP model for getting read-only data about users and groups from Active Directory.
 *
 * @author gozoro <gozoro@yandex.ru>
 */
class Ldap
{
	const ERRNO_NO_CONNECTION = -1;
	const ERRNO_INVALID_CREDENTIALS = 49;


	private $_username;
	private $_password;
	private $_hosts;
	private $_dnsSuffixes = [];
	private $_domainName;
	private $_timeout;
	private $_protocolVersion = 3;

	private $_link;



	/**
	 * Constructor of LDAP model.
	 *
	 * @param array $config
	 */
	public function __construct($config)
	{
		if(!function_exists('ldap_connect'))
		{
			throw new LdapConfigException("PHP ldap-extension is not installed.");
		}

		if(empty($config))
		{
			throw new LdapConfigException("Config is undefined.");
		}


		if(!empty($config['username']))
			$this->_username = $config['username'];
		else
			throw new LdapConfigException("Parameter [username] must be set.");

		if(!empty($config['password']))
			$this->_password = $config['password'];
		else
			throw new LdapConfigException("Parameter [password] must be set.");

		if(!empty($config['hosts']))
			$this->_hosts = (array)$config['hosts'];
		else
			throw new LdapConfigException("Parameter [hosts] must be set. The parameter must contain an array of hosts domain controllers.");

		if(!empty($config['domainName']))
		{
			$domainName = strtolower(trim($config['domainName']));
			$domainName = str_replace('@', '', $domainName);
			$domainName = preg_replace('/^\./', '', $domainName);

			$this->_domainName = $domainName;
			$this->_dnsSuffixes[] = $domainName;

		}
		else
			throw new LdapConfigException("Parameter [domainName] must be set. The parameter must contain the full domain name (e.g., mydomain.net).");

		if(!empty($config['dnsSuffixes']))
		{
			$suffixes = (array)$config['dnsSuffixes'];

			foreach($suffixes as $suffix)
			{
				$suffix = str_replace('@', '', trim($suffix));
				$suffix = preg_replace('/^\./', '', $suffix);
				$this->_dnsSuffixes[] = strtolower(trim($suffix));
			}
		}


		if(!empty($config['timeout']))
			$this->_timeout = (int)$config['timeout'];

		if(!empty($config['protocolVersion']))
		{
			$protocols = [2,3];
			$protocol = (int)$config['protocolVersion'];

			if(in_array($protocol, $protocols))
				$this->_protocolVersion = $protocol;
			else
				throw new LdapConfigException("Unknow protocol version.");
		}


		$this->init();
	}


	public function __destruct()
	{
		$this->disconnect();
	}

    /**
     * Initializes the object.
     * This method is invoked at the end of the constructor after the object is initialized with the
     * given configuration.
     */
	public function init()
	{
		$this->connect();
	}

	/**
	 * Returns component user logon name.
	 * @return string
	 */
	public function getUsername()
	{
		return $this->_username;
	}

	/**
	 * Returns component password.
	 * @return string
	 */
	public function getPassword()
	{
		return $this->_password;
	}

	/**
	 * Returns array of hosts domain-controllers.
	 * @return array of string
	 */
	public function getHosts()
	{
		return $this->_hosts;
	}

	/**
	 * Retuns domain name.
	 * @return string
	 */
	public function getDomainName()
	{
		return $this->_domainName;
	}

	/**
	 * Returns array of DNS suffixes.
	 * @return array
	 */
	public function getDnsSuffixes()
	{
		return $this->_dnsSuffixes;
	}

	/**
	 * Returns the timeout connection to LDAP-server.
	 * @return int
	 */
	public function getTimeout()
	{
		return $this->_timeout;
	}

	/**
	 * Returns the protocol version.
	 * @return int
	 */
	public function getProtocolVersion()
	{
		return $this->_protocolVersion;
	}


	/**
	 * Connects to the LDAP-server.
	 * @return resource
	 */
	protected function connect()
	{
		$link = \ldap_connect();

		$space_host = implode(' ', $this->getHosts());

		\ldap_set_option($link, LDAP_OPT_HOST_NAME, $space_host);


		if(isset($this->_timeout) and $this->_timeout > 0)
			\ldap_set_option($link, LDAP_OPT_NETWORK_TIMEOUT, $this->_timeout);

		\ldap_set_option($link, \LDAP_OPT_PROTOCOL_VERSION, $this->getProtocolVersion());
		\ldap_set_option($link, \LDAP_OPT_REFERRALS, 0);

		return $this->_link = $link;
	}

	/**
	 * Disconnects from the LDAP-server.
	 * @return boolean
	 */
	protected function disconnect()
	{
        if(is_resource($this->_link))
        {
			if(@\ldap_unbind($this->_link))
			{
				$this->_link = null;
				return true;
			}
			return false;
		}
		return true;
	}


	/**
	 * Checks connection to LDAP-server.
	 * Returns FALSE when no connection.
	 *
	 * @return boolean
	 */
	public function checkConnection()
	{
		if(@\ldap_bind($this->_link))
		{
			$errorNumber = $this->getErrorNumber();

			if($errorNumber == self::ERRNO_NO_CONNECTION)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
		else
			return false;
	}

	/**
	 * Returns the error message.
	 *
	 * @return string
	 */
	public function getErrorMessage()
	{
		return \ldap_error($this->_link);
	}

	/**
	 * Returns the error number.
	 *
	 * @return int
	 */
	public function getErrorNumber()
	{
		 return \ldap_errno($this->_link);
	}

	/**
	 * Search LDAP tree.
	 *
	 * Examples:<br />
	 *
	 * $filter = "samaccountname=johnSmith";<br />
	 * $filter = "mail=johnSmith@example.com";<br />
	 * $filter = "(&(objectCategory=group)(sAMAccountName=admins))";<br />
	 * $filter = "(&(objectClass=user)( objectCategory=person)(userPrincipalName=johnSmith@mydomain.net))";<br />
	 * $filter = "(&(objectClass=user)(memberof=CN=admins,OU=admins2folder,DC=rg,DC=net))";<br />
	 *
	 * @param string $filter filter
	 * @param array $attributes [optional] result attributes. Default value: Ldap::defaultLdapAttributes()
	 * @param string $dn [optional] distinguished name. Default value: $this->getBaseDN()
	 * @return array result tree
	 */
	public function search($filter, $attributes = null, $dn = null)
	{
		if( !(@\ldap_bind($this->_link, $this->getUsername(), $this->getPassword())) )
		{
			$errmsg = $this->getErrorMessage();
			$domainName = $this->getDomainName();
			throw new LdapException("Connection failed to establish to $domainName. $errmsg.");
		}

		if(is_null($attributes))
		{
			$attributes = static::defaultLdapAttributes();
		}

		if(is_null($dn))
		{
			$dn = $this->getBaseDN();
		}

		$result = \ldap_search($this->_link, $dn, $filter, $attributes);
		$data = $this->searchDecode($result);

		if($data and isset($data['count']) and $data['count'] > 0)
		{
			$count = $data['count'];

			unset($data['count']);

			$resultData = [];
			foreach($data as $index => $row)
			{
				if(isset($row['dn']))
					$resultData[$index]['dn'] = $row['dn'];

				foreach($attributes as $fieldName)
				{
					$fieldName = strtolower($fieldName);

					if(isset($row[$fieldName]) and $row[$fieldName]['count'])
					{
						if($row[$fieldName]['count'] == 1)
							$resultData[$index][$fieldName] = $row[$fieldName][0];
						else
						{
							unset($row[$fieldName]['count']);
							$resultData[$index][$fieldName] = $row[$fieldName];
						}
					}
					else
					{
						$resultData[$index][$fieldName] = null;
					}
				}
			}

			return $resultData;
		}
		else
			return null;

	}

	/**
	 * Decodes the search result.
     *
	 * @param resource $searchResult result of method search()
	 * @return array
	 */
	protected function searchDecode($searchResult)
	{
		if(!$this->_link)
		{
			return [];
		}

		return \ldap_get_entries($this->_link, $searchResult);
	}


	/**
	 * Returns domain distinguished name.
	 *
	 * @return string
	 */
	public function getBaseDN()
	{
		$domain = $this->getDomainName();

		$parts = explode('.', $domain);
		$baseDN = [];
		foreach($parts as $dn)
		{
			$baseDN[] = 'DC='.$dn;
		}
		return implode(',', $baseDN);
	}





	/**
	 * Returns an array of attribute names as default array for method search().
	 *
	 * @return array
	 */
	static function defaultLdapAttributes()
	{
		return array('samaccountname',
			'objectCategory', 'objectClass', 'objectSID', 'objectGUID',
			'name', 'description',
			'whenchanged', 'whencreated',
			'cn', 'memberOf'
			);
	}

	/**
	 * Validates allowable characters.
	 *
	 * @param string $string
	 * @return bool
	 */
	static function validateCharacters($string)
	{
		return (preg_match('/^[-a-z_|\d|\.]+$/', $string)
					and !preg_match('/^[\.]/', $string)
					and !preg_match('/[\.]$/', $string)
					and !preg_match('/\.{2,}/', $string)
					);
	}


	/**
	 * Cuts $domainUsername to domain and username. If the domain is missing its value will be $defaultDomain.
	 * If $domainUsername is not correct the method returns FALSE.
	 *
	 *
	 * @param string $domainUsername username with domain like 'johnSmith@mydomain.net' or 'mydomain\johnSmith'
	 * @param string $defaultDomain default domain. For example mydomain.net or DNS-suffix (e.g. mydomain)
	 * @return array [domain, username]
	 */
	static function parseUsername($domainUsername, $defaultDomain)
	{
		$domainUsername = trim($domainUsername);
		$domainUsername = strtolower($domainUsername);
		$parsed = [];


		$isPrincipal   = preg_match('/@/', $domainUsername);
		$isPreWindows2000 = preg_match('/\\\/', $domainUsername);


		if($isPrincipal and !$isPreWindows2000)
		{
			// $domainUsername as 'johnSmith@mydomain.net'
			$parts = explode('@', $domainUsername);
		}
		elseif(!$isPrincipal and $isPreWindows2000)
		{
			// $domainUsername as 'mydomain\johnSmith'
			$parts = explode('\\', $domainUsername);
			$parts = array_reverse($parts);
		}
		elseif(!$isPrincipal and !$isPreWindows2000)
		{
			// $domainUsername as 'johnSmith'
			$parts = array($domainUsername, $defaultDomain);
		}
		else
		{
			return false;
		}


		if(count($parts) == 2 and trim($parts[0]) != '' and trim($parts[1]) != '')
		{
			$username = trim($parts[0]);
			$domain   = trim($parts[1]);

			if(static::validateCharacters($username) and static::validateCharacters($domain))
			{
				return array('domain'=>$domain, 'username'=>$username);
			}
			else
			{
				return false;
			}
		}
		else
			return false;
	}

	/**
	 * Finds LdapUser instance by user logon name.
	 *
	 * @param string $domainUsername user name like johnSmith, mydomain\johnSmith, johnSmith@mydomain.net
	 * @return LdapUser|NULL
	 * @throws LdapException
	 */
	public function findUser($domainUsername)
	{
		$parsedUsername = static::parseUsername($domainUsername, $this->getDomainName());

		if($parsedUsername === false)
		{
			throw new LdapException('The username you searched is not correct.');
		}

		$username = $parsedUsername['username'];
		$domain   = $parsedUsername['domain'];


		if(!in_array($domain, $this->getDnsSuffixes()))
		{
			throw new LdapException("The user's domain does not match the connection domain.");
		}

		$userPrincipalName = $username.'@'.$domain;

		$defaultAttributes = LdapUser::defaultAttributes();

		$data = $this->search('(&(objectClass=user)( objectCategory=person)(samaccountname='.$username.'))', $defaultAttributes);

		if($data and isset($data[0]))
		{
			return new LdapUser($this, $data[0]);
		}
		else
		{
			return null;
		}
	}

	/**
	 * Finds LdapUser instances by mask of user logon name.
	 *
	 * @param string $usernameMask mask of user logon name like john, johnSmith, john*, *hnSmi*, mydomain\john*, j*Smith@mydomain.net
	 * @return array of LdapUser
	 * @throws LdapException
	 */
	public function findUsers($usernameMask)
	{
		$domainUsername = str_replace('*', '', $usernameMask);

		$parsedUsername = static::parseUsername($domainUsername, $this->getDomainName());

		if($parsedUsername === false)
		{
			throw new LdapException('The username you searched is not correct.');
		}

		$domain = $parsedUsername['domain'];

		$suffixes = $this->getDnsSuffixes();
		if(!in_array($domain, $suffixes))
		{
			throw new LdapException("The user's domain does not match the connection domain.");
		}

		$defaultAttributes = LdapUser::defaultAttributes();
		$data = $this->search('(&(objectClass=user)( objectCategory=person)(samaccountname='.$usernameMask.'))', $defaultAttributes);

		if($data and is_array($data))
		{
			$users = [];

			foreach($data as $user_data)
			{
				$users[] = new LdapUser($this, $user_data);
			}

			return $users;
		}
		else
		{
			return [];
		}
	}



	/**
	 * Finds LdapUser instance by object GUID.
	 *
	 * @param string $objectGUID user object GUID like "1ba5b8ff-b80b-40d4-ae45-7418f8eedd6a"
	 * @return LdapUser|NULL
	 * @throws LdapException
	 */
	public function findUserByObjectGUID($objectGUID)
	{
		$binaryObjectGUID = static::convertObjectGUIDToBinary($objectGUID);

		$defaultAttributes = LdapUser::defaultAttributes();
		$data = $this->search('(&(objectClass=user)( objectCategory=person)(objectGUID='.$binaryObjectGUID.'))', $defaultAttributes);

		if($data and isset($data[0]))
		{
			return new LdapUser($this, $data[0]);
		}
		else
		{
			return null;
		}

		return $this;
	}


	/**
	 * Finds LdapGroup instance by group name.
	 *
	 * @param string $groupName
	 * @return LdapGroup|NULL
	 */
	public function findGroup($groupName)
	{
		if(!static::validateCharacters($groupName))
		{
			throw new LdapException('The group name you searched is not correct.');
		}

		$defaultAttributes = LdapGroup::defaultAttributes();

		$groups = [];

		$ldap_group = $this->search('(&(objectClass=group)(name='.$groupName.'))', $defaultAttributes);

		if($ldap_group and isset($ldap_group[0]))
		{
			return new LdapGroup($this, $ldap_group[0]);
		}
		else
		{
			return null;
		}
	}


	/**
	 * Validate user logon name. Returns TRUE if user logon name is correct.
	 * Returns FALSE if user logon name is not correct.
	 *
	 * Correct $username for example:
	 * - john
	 * - mydomain\john
	 * - john@mydomain.net
	 * - john@mydomain
	 *
	 * @param string $username
	 * @return bool
	 */
	public function validateUsername($username)
	{
		return (bool)static::parseUsername($username, $this->getDomainName());
	}

	/**
	 * Validate password. Returns TRUE if the password allows authentication.
	 *
	 * @param string $principalName user logon name like john@mydomain.net
	 * @param string $password
	 * @return boolean
	 */
	public function validatePassword($principalName, $password)
	{
		if($password)
		{
			if(@\ldap_bind($this->_link, $principalName, $password))
			{
				return true;
			}
			else
			{
				$errorNumber = $this->getErrorNumber();

				if($errorNumber == self::ERRNO_INVALID_CREDENTIALS)
				{
					return false;
				}
				else
				{
					throw new LdapException( $this->getErrorMessage() );
				}
			}
		}
		else
		{
			return false;
		}
	}

	/**
	 * Converts a binary SID representation to a string representation.
	 *
	 * @param string $binaryObjectSID binary object SID
	 * @return string
	 */
	public static function convertObjectSIDBinayToString($binaryObjectSID)
	{
		$hex_sid  = bin2hex($binaryObjectSID);
		$rev      = hexdec(substr($hex_sid, 0, 2));
		$subcount = hexdec(substr($hex_sid, 2, 2));
		$auth     = hexdec(substr($hex_sid, 4, 12));
		$result   = "$rev-$auth";

		for ($x=0; $x < $subcount; $x++)
		{
			$hex = substr($hex_sid, 16 + ($x * 8), 8);
			$little_endian = '';
			for ($xx = strlen($hex) - 2; $xx >= 0; $xx = $xx - 2)
			{
				$little_endian .= substr($hex, $xx, 2);
			}

			$subauth[$x] = hexdec($little_endian);
			$result .= "-" . $subauth[$x];
		}

		return 'S-' . $result;
	}

	/**
	 * Converts a binary GUID representation to a string representation.
	 *
	 * @param string $binaryObjectGUID binary object GUID
	 * @return string
	 */
	public static function convertObjectGUIDBinaryToString($binaryObjectGUID)
	{
		$hex = bin2hex($binaryObjectGUID);

		if(strlen($hex) == 32)
		{
			$a = substr($hex, 6, 2) . substr($hex, 4, 2) . substr($hex, 2, 2) . substr($hex, 0, 2);
			$b = substr($hex, 10, 2) . substr($hex, 8, 2);
			$c = substr($hex, 14, 2) . substr($hex, 12, 2);
			$d = substr($hex, 16, 4);
			$e = substr($hex, 20, 12);

			return strtolower($a.'-'.$b.'-'.$c.'-'.$d.'-'.$e);
		}
		else
			throw new LdapException("Invalid GUID format. The unpacked GUID string does not match the size of 32 characters.");
	}



	/**
	 * Converts a string GUID representation to a binary representation.
	 *
	 * @param string $GUID string GUID, e.g. 1ba5b8ff-b80b-40d4-ae45-7418f8eedd6a
	 * @return string of binary or FALSE on failure
	 */
	public static function convertObjectGUIDToBinary($GUID)
	{
		$GUID = strtolower($GUID);
		$hex = str_replace('-', '', $GUID);

		if(strlen($hex) == 32)
		{
			$a = substr($hex, 6, 2) . substr($hex, 4, 2) . substr($hex, 2, 2) . substr($hex, 0, 2);
			$b = substr($hex, 10, 2) . substr($hex, 8, 2);
			$c = substr($hex, 14, 2) . substr($hex, 12, 2);
			$d = substr($hex, 16, 4);
			$e = substr($hex, 20, 12);

			return hex2bin($a.$b.$c.$d.$e);
		}
		else
			throw new LdapException("Invalid GUID format.");
	}



	/**
	 * Converts a ldap-timestamp to date with format Y-m-d H:i:s.
	 *
	 * @param string $ldapTimestamp
	 * @param string $format date format
	 * @return string|NULL
	 */
    public static function convertLdapTimestampToDate($ldapTimestamp, $format = 'Y-m-d H:i:s')
	{
		$ts = $ldapTimestamp / 10000000 - 11644473600;

		if($ts > 32503669200)
		{
			return null;
		}

		return date($format, $ts);
	}

	/**
	 * Converts date from yyyymmddhhmmsst to date fromat.
	 *
	 * @param string $yyyymmddhhmmsst The date as returned by LDAP in format yyyymmddhhmmsst
	 * @param string $format date format
	 * @return string
	 */
    public static function convertYYYYMMDDHHmmssToDate($yyyymmddhhmmsst, $format = 'Y-m-d H:i:s')
	{
		$year   = substr($yyyymmddhhmmsst, 0, 4);
		$month  = substr($yyyymmddhhmmsst, 4, 2);
		$day    = substr($yyyymmddhhmmsst, 6, 2);
		$hour   = substr($yyyymmddhhmmsst, 8, 2);
		$minute = substr($yyyymmddhhmmsst, 10, 2);
		$second = substr($yyyymmddhhmmsst, 12, 2);
		$ts     = mktime($hour, $minute, $second, $month, $day, $year);

		return date($format, $ts);
	}
}

/**
 * Ldap exception.
 */
class LdapException extends \Exception{}

/**
 * LdapConfigException represents an exception caused by incorrect ldap-object configuration.
 */
class LdapConfigException extends LdapException{}