# A distribution list plugin for ldap

The plugin reads all objects defined by the filter
from ldap and if groupType is not a securityGroup (0x80000000)
expands the members to their main email addresses.

## Config

```
settings:
  refresh_interval: 600
  url: ldaps://samba.example.com:636
  basedn: OU=ExampleOU,DC=example,DC=com
  bind:
  	dn: CN=Management,DC=example,DC=com
  	pwd: examplePassword

groups:
  filter: (&(objectClass=group)(|(mail=*)(proxyAddresses=*)))

users:
  filter: (&(objectClass=person)(|(mail=*)(proxyAddresses=*)))
```

Refresh interval gives the interval in which ldap is checked for new configuration settings.

Groups filter all groups that should be checked. All members of the groups are filled from the users query.
All users are also checked.

Errors are shown if groups use the same emails, or users use the same email.


## Usage

Designed for haraka-plugin-plugin_manager