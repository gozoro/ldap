<?php

namespace gozoro\ldap;


/**
 * LDAP model for getting read-only data about users and groups from Active Directory or other LDAP-servers.
 *
 * @author gozoro <gozoro@yandex.ru>
 */
class Ldap
{
	const ERRNO_NO_CONNECTION = -1;
	const ERRNO_INVALID_CREDENTIALS = 49;


	/**
	 * Service username to bind.
	 * @var string
	 */
	private $_username;

	/**
	 * Service password to bind.
	 * @var string
	 */
	private $_password;

	/**
	 * Array of ldap-server hosts.
	 * @var array of string
	 */
	private $_hosts = [];

	/**
	 * Here you can specify additional dns suffixes for complex domains.
	 * @var array of string
	 */
	private $_dnsSuffixes = [];

	/**
	 * Domain name, for example "example.net".
	 * @var string
	 */
	private $_domainName;

	/**
	 * Sets timeout to the `LDAP_OPT_NETWORK_TIMEOUT` option.
	 * @var int
	 */
	private $_timeout;

	/**
	 * Sets protocol version (2 or 3) to LDAP_OPT_PROTOCOL_VERSION option. By default version: 3.
	 * @var int
	 */
	private $_protocolVersion = 3;

	/**
	 * Link identifier
	 * @var \Ldap\Connection
	 */
	private $_link;

	private $_eventHandlers = [];

	/**
	 * When TRUE the ldap_start_tls() function is called after connect to LDAP-server
	 * @var bool
	 */
	private $_starttls = false;

	/**
	 * SASL mechanism.
	 * Empty string is bind without SASL.
	 * @var string
	 */
	private $_saslMech = '';


	/**
	 * The SASL mechanism for validating the user password when using SASL.
	 * By Default DIGEST-MD5.
	 * @var string
	 */
	private $_saslPassMech = 'DIGEST-MD5';

	/**
	 * SASL realm
	 * @var string
	 */
	private $_saslRealm;


	/**
	 * Constructor of LDAP model.
	 *
	 * - $config['username']        - service username to bind.
	 * - $config['password']        - service password to bind.
	 * - $config['hosts']           - array of ldap-server hosts.
	 * - $config['domainName']      - domain name, for example "example.net".
	 * - $config['dnsSuffixes']     - here you can specify additional dns suffixes for complex domains.
	 * - $config['timeout']         - timeout to the LDAP_OPT_NETWORK_TIMEOUT option.
	 * - $config['protocolVersion'] - protocol version (2 or 3) to LDAP_OPT_PROTOCOL_VERSION option. By default 3.
	 *
	 * - $config['beforeConnect']    - the event handler function for example `function(Ldap $ldap){ ... }`.
	 * - $config['afterConnect']     - the event handler function for example `function(Ldap $ldap){ ... }`.
	 * - $config['beforeClose']      - the event handler function for example `function(Ldap $ldap){ ... }`.
	 * - $config['afterClose']       - the event handler function for example `function(Ldap $ldap){ ... }`.
	 * - $config['beforeSearch']     - the event handler function for example `function(Ldap $ldap){ ... }`.
	 * - $config['afterSearch']      - the event handler function for example `function(Ldap $ldap){ ... }`.
	 *
	 * - $config['starttls']       - start TLS after connect to LDAP-server.
	 * - $config['SASL_MECH']      - here you can set SASL mechanism. For example: GSSAPI, DIGEST-MD5, etc. By default (empty string) SALS is disabled.
	 * - $config['SASL_PASS_MECH'] - the SASL mechanism for validating the user password when using SASL. By default DIGEST-MD5.
	 * - $config['SASL_REALM']     - the realm when using SASL. if realm undefind then realm sets from 'domainName'.
	 *
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

		if(!empty($config['password']))
			$this->_password = $config['password'];

		if(!empty($config['hosts']))
		{
			$config['hosts'] = (array)$config['hosts'];
			foreach($config['hosts'] as $url)
			{
				$parts = parse_url($url);

				if(count($parts) == 1 and !empty($parts['path']))
				{
					$host = $parts['path'];
				}
				else
				{
					if(empty($parts['host']))
						throw new LdapConfigException("Host undefined.");

					$host = $parts['host'];

					if(!empty($parts['port']))
						$host .= ":".$parts['port'];
				}

				$this->_hosts[] = $host;
			}
		}
		else
			throw new LdapConfigException("Parameter [hosts] must be set. The parameter must contain an array of hosts LDAP-servers.");

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


		if(!empty($config['beforeConnect']))
			$this->addEventHandler('beforeConnect', $config['beforeConnect']);

		if(!empty($config['afterConnect']))
			$this->addEventHandler('afterConnect', $config['afterConnect']);

		if(!empty($config['beforeClose']))
			$this->addEventHandler('beforeClose', $config['beforeClose']);

		if(!empty($config['afterClose']))
			$this->addEventHandler('afterClose', $config['afterClose']);

		if(!empty($config['beforeSearch']))
			$this->addEventHandler('beforeSearch', $config['beforeSearch']);

		if(!empty($config['afterSearch']))
			$this->addEventHandler('afterSearch', $config['afterSearch']);


		if(!empty($config['starttls']))
		{
			$this->_starttls = (bool)$config['starttls'];
		}

		if(!empty($config['SASL_MECH']))
		{
			$this->_saslMech = (string)$config['SASL_MECH'];
		}

		if(!empty($config['SASL_PASS_MECH']))
		{
			$this->_saslPassMech = (string)$config['SASL_PASS_MECH'];
		}

		if(empty($config['SASL_REALM']))
		{
			$this->_saslRealm = (string)$config['domainName'];
		}
		else
		{
			$this->_saslRealm = (string)$config['SASL_REALM'];
		}

		$this->connect();
	}


	public function __destruct()
	{
		$this->close();
	}

	/**
	 * Adds event handler function.
	 * @param string $eventName
	 * @param callable $handlerFunc
	 */
	private function addEventHandler($eventName, $handlerFunc)
	{
		if(\is_callable($handlerFunc))
		{
			$this->_eventHandlers[$eventName] = $handlerFunc;
		}
		else
			throw new LdapConfigException("Handler '$eventName' is not callable.");
	}

	/**
	 * Triggers event
	 */
	private function triggerEvent($eventName)
	{
		if(isset( $this->_eventHandlers[$eventName] ) and \is_callable( $this->_eventHandlers[$eventName] ))
		{
			$f = $this->_eventHandlers[$eventName];
			$f( $this );
		}
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
	 * Returns TRUE wnen used STARTTLS
	 * @return bool
	 */
	public function isStartTLS()
	{
		return $this->_starttls;
	}

	/**
	 * Returns SASL mechanism.
	 * Empty string is means SALS disabled.
	 * @return string
	 */
	public function getSaslMech()
	{
		return $this->_saslMech;
	}

	/**
	 * Returns SASL mechanism of validate user password.
	 * @return string
	 */
	public function getSaslPassMech()
	{
		return $this->_saslPassMech;
	}

	/**
	 * Returns SASL realm
	 * @return string
	 */
	public function getSaslRealm()
	{
		return $this->_saslRealm;
	}

	/**
	 * Connects to LDAP-server without events.
	 * @return resource
	 */
	private function _connect()
	{
		$link = \ldap_connect();
		$this->_link = $link;

		$space_host = implode(' ', $this->getHosts());

		\ldap_set_option($link, \LDAP_OPT_HOST_NAME, $space_host);

		if(isset($this->_timeout) and $this->_timeout > 0)
			\ldap_set_option($link, \LDAP_OPT_NETWORK_TIMEOUT, $this->_timeout);

		\ldap_set_option($link, \LDAP_OPT_PROTOCOL_VERSION, $this->getProtocolVersion());
		\ldap_set_option($link, \LDAP_OPT_REFERRALS, 0);


		if($this->_starttls)
		{
			if(!\ldap_start_tls($link))
			{
				throw new LdapException("Failed start TLS");
			}
		}

		if(!empty($this->_saslMech))
		{
			// SASL authentication
			if (!(@ldap_sasl_bind($link, NULL, $this->_password, $this->_saslMech, $this->_saslRealm, $this->_username))) {
				throw new LdapException($this->_saslMech." error: " . ldap_error($link));
			}
		}

		return $this->_link;
	}

	/**
	 * Connects to the LDAP-server.
	 * @return resource
	 */
	public function connect()
	{
		if(!$this->_link)
		{
			$this->triggerEvent('beforeConnect');
			$this->_connect();
			$this->triggerEvent('afterConnect');
		}
		return $this->_link;
	}

	/**
	 * Returns link indentifier.
	 */
	public function getLink()
	{
		return $this->_link;
	}

	/**
	 * Returns TRUE when SASL mechanism is used for binding.
	 * @var bool
	 */
	private function useSASL()
	{
		return (bool)$this->_saslMech;
	}

	private function bind()
	{
		if(!$this->_link)
		{
			throw new LdapException("No connection");
		}

		if($this->useSASL())
		{
			$this->_connect();
		}
		else
		{
			if(!(\ldap_bind($this->_link, $this->_username, $this->_password)) )
			{
				throw new LdapException("Binding error: " . $this->getErrorMessage());
			}
		}

		return true;
	}




	/**
	 * Unbinds from the LDAP-server.
	 * @return boolean
	 */
	private function unbind()
	{
        if($this->_link)
        {
			if(@\ldap_unbind($this->_link))
			{
				$this->_link = null;
				return true;
			}
		}
		return false;
	}


	/**
	 * Closes the connection to the LDAP server.
	 * @var bool
	 */
	public function close()
	{
		if($this->_link)
		{
			$this->triggerEvent('beforeClose');

			if($this->unbind())
			{
				$this->triggerEvent('afterClose');
				return true;
			}
		}

		return false;
	}


	/**
	 * Checks connection to LDAP-server.
	 * Returns FALSE when no connection.
	 *
	 * @return boolean
	 */
	public function checkConnection()
	{
		if($this->_link)
		{
			$errorNumber = $this->getErrorNumber();
			return !($errorNumber == self::ERRNO_NO_CONNECTION);
		}

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
		$this->triggerEvent('beforeSearch');

		$this->bind();

		if(is_null($attributes))
		{
			$attributes = static::defaultLdapAttributes();
		}

		if(is_null($dn))
		{
			$dn = $this->getBaseDN();
		}

		$result = \ldap_search($this->_link, $dn, $filter, $attributes);

		$this->triggerEvent('afterSearch');

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
	 * @param \Ldap\Result $searchResult result of method search()
	 * @return array|false
	 */
	protected function searchDecode($searchResult)
	{
		if(!$this->_link)
		{
			return [];
		}

		if(empty($searchResult))
		{
			return false;
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
	 * @param string $username user logon name like john or john@mydomain.net or mydomain\john
	 * @param string $password
	 * @return boolean
	 */
	public function validatePassword($username, $password)
	{
		if(!$password or !$username) return false;

		$defaultDomain = $this->getDomainName();
		$parsed = self::parseUsername($username, $defaultDomain);

		$samaccountName = $parsed['username'];
		$domain         = $parsed['domain'];


		if($this->useSASL())
		{
			$ok = @ldap_sasl_bind($this->_link, null, $password, $this->_saslPassMech, $this->_saslRealm, $username);
		}
		else
		{
			$ok = @\ldap_bind($this->_link, $samaccountName.'@'.$domain, $password);
		}

		if($ok)
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