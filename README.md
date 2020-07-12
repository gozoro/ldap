# ldap
A simple tool for getting user data from Active Directory.


Installation
------------
```code
	composer require gozoro/ldap
```



Usage
-----

```php

$config = [
	'username'   => 'domain_admin',
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