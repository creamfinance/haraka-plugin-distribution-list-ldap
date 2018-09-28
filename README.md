# A distribution list plugin for ldap

The plugin reads all objects defined by the filter
from ldap and if groupType is not a securityGroup (0x80000000)
expands the members to their main email addresses.

## Config

```
main:
  server: ldaps://samba.example.com:636
  binddn: CN=Management,DC=example,DC=com
  bindpw: examplePassword
  basedn: OU=ExampleOU,DC=example,DC=com
  filter: (&(objectClass=group)(|(mail=%u)(proxyAddresses=%u)))
```

%u in the filter is replaced by the email in RCPT.


## Usage

Designed for haraka-plugin-plugin_manager