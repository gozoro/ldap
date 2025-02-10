# ldap
A simple tool for getting user data from Active Directory.


Installation
------------
```code
	composer require gozoro/ldap
```




Configuration
-----

- **username** - service username to bind.
- **password** - service password to bind.
- **hosts** - array of ldap-server hosts.
- **domainName** - domain name, for example "example.net".
- **dnsSuffixes** - here you can specify additional dns suffixes for complex domains.
- **timeout** - sets timeout to the `LDAP_OPT_NETWORK_TIMEOUT` option.
- **protocolVersion** - sets protocol version (2 or 3) to `LDAP_OPT_PROTOCOL_VERSION` option. By default version: 3.

- **beforeConnect** - the event handler function for example `function(Ldap $ldap){ ... }`.
- **afterConnect**  - the event handler function for example `function(Ldap $ldap){ ... }`.
- **beforeClose**   - the event handler function for example `function(Ldap $ldap){ ... }`.
- **afterClose**    - the event handler function for example `function(Ldap $ldap){ ... }`.
- **beforeSearch**  - the event handler function for example `function(Ldap $ldap){ ... }`.
- **afterSearch**   - the event handler function for example `function(Ldap $ldap){ ... }`.
	
- **starttls** - start TLS after connect to LDAP-server.
- **SASL**     - here you can set [SASL](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) (Simple Authentication and Security Layer) mechanism. For example: `GSSAPI`,`DIGEST-MD5`, etc. By default - empty string (SALS is disabled).


#### Popular SASL mechanisms

- [NTLM](https://en.wikipedia.org/wiki/NTLM) - an NT LAN Manager authentication mechanism.
- [GSSAPI](https://en.wikipedia.org/wiki/GSSAPI) - The Generic Security Service Application Program Interface is an application programming interface for programs to access security services. It is used for Kerberos V5 authentication via the GSSAPI.
- [DIGEST-MD5](https://en.wikipedia.org/wiki/Digest_access_authentication) - Digest access authentication 
- etc



Usage
-----

```php

$config = [
	'username'   => 'admin',
	'password'   => '12345',
	'hosts'      => ['ldap1.example.net', 'ldap2.example.net'],
	'domainName' => 'example.net',
];


$ldap = new \gozoro\ldap\Ldap($config);

$user = $ldap->findUser('john');

print $user->getPrincipalName(); // john@example.net
print $user->getDisplayName();   // John Smith
print $user->getLastLogonTime(); // 2020-07-12 14:23:17
print $user->getObjectGuid();    // 1ba5b8ff-b80b-40d4-ae45-7418f8eedd6a
print_r($user->getGroupNames()); // Array(0=>'admins', 'users')

$userPassword = 'qwerty';

if($user->validatePassword($userPassword))
{
	print 'password: OK';
}

foreach($user->getGroups() as $userGroup)
{
	print $userGroup->getName();
	print $userGroup->getObjectGUID();
}


```


Usage with SASL
-----


```php

$config = [
	'hosts'      => ['ldap1.example.net', 'ldap2.example.net'],
	'domainName' => 'example.net',
	'protocolVersion' => 3,

	'SASL' => 'GSSAPI',

	'beforeConnect' => function($ldap){
		$cmd = "kinit -k -t /etc/keytabs/my.access.keytab ldap/example.net@EXAMPLE.NET 2>&1";
		exec($cmd, $output, $result);
		if ($result !== 0) {
			throw new \Exception("kinit failed: " . implode("\n", $output));
		}
	},

	'afterClose' => function(){
		$cmd = "kdestroy 2>&1";
		exec($cmd, $output, $result);
		if ($result !== 0) {
			throw new \Exception("kdestroy failed: " . implode("\n", $output));
		}
	},
];

// Authentication with SASL mechanism GSSAPI (Kerberos v5)
$ldap = new \gozoro\ldap\Ldap($config);

// Validate users's password with SASL mechanism DIGEST-MD5
$user = $ldap->validatePassword('john', 'qwerty', 'DIGEST-MD5');

```