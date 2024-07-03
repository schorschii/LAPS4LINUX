# LAPS4LINUX 💘 OpenLDAP
This document describes how LAPS(4LINUX) can be used with OpenLDAP. This guide assumes that you already have an OpenLDAP server set up and running. A short overview / cookbook for a basic OpenLDAP setup can be found in my [OpenLDAP Cheat Sheet](https://gist.github.com/schorschii/0dcd19d4abb74bd3d52de12bff91657b).

All LAPS4LINUX features can be used with OpenLDAP **except password encryption**, since the encryption relies on proprietary RPC calls only available on Windows Server.

## 1. Kerberos Setup
The LAPS runner uses Kerberos for authentication, therefore you need to set up Kerberos authentication for your OpenLDAP. [This guide](https://ubuntu.com/server/docs/how-to-set-up-kerberos-with-openldap-backend) from Ubuntu describes how to configure a Kerberos server (can be run on the same server as known from Microsoft AD) by using your OpenLDAP as backend.

After your Kerberos server is running, you need to create a principal and a corresponding keytab for your OpenLDAP server to enable Kerberos authentication in your OpenLDAP.
```
$ kadmin.local
addprinc -randkey ldap/openldap.example.com
ktadd -k /etc/krb5.keytab ldap/openldap.example.com@EXAMPLE.COM
```

## 2. Extend the Schema
You need to add attributes to your schema where to store the administrator passwords. We are using the same names and OIDs like the [original attributes from Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference), but the syntax OIDs are replaced with the corresponding OpenLDAP counterparts.

Add this dynamic config via `ldapmodify -Y EXTERNAL -H ldapi:///`:
```
dn: cn=laps,cn=schema,cn=config
changetype: add
objectClass: olcSchemaConfig
cn: laps
olcAttributeTypes: {0}( 1.2.840.113556.1.6.44.1.1 NAME 'msLAPS-PasswordExpirationTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
olcAttributeTypes: {1}( 1.2.840.113556.1.6.44.1.2 NAME 'msLAPS-Password' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: {2}( 1.2.840.113556.1.6.44.1.3 NAME 'msLAPS-EncryptedPassword' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcAttributeTypes: {3}( 1.2.840.113556.1.6.44.1.4 NAME 'msLAPS-EncryptedPasswordHistory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcAttributeTypes: {4}( 1.2.840.113556.1.6.44.1.5 NAME 'msLAPS-EncryptedDSRMPassword' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcAttributeTypes: {5}( 1.2.840.113556.1.6.44.1.6 NAME 'msLAPS-EncryptedDSRMPasswordHistory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcAttributeTypes: {5}( 1.2.840.113556.1.6.44.1.7 NAME 'msLAPS-CurrentPasswordVersion' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )

olcObjectClasses: {0}( 1.1.3.7.1 NAME 'computer' DESC 'Computer object' SUP person STRUCTURAL MAY ( msLAPS-PasswordExpirationTime $ msLAPS-Password $ msLAPS-EncryptedPassword $ msLAPS-EncryptedPasswordHistory $ msLAPS-EncryptedDSRMPassword $ msLAPS-EncryptedDSRMPasswordHistory $ msLAPS-CurrentPasswordVersion ) )
```

## 3. Create Appropriate ACLs
You need to add ACLs so that only a group of administrators can read and the computer itself can write the LAPS attributes.

OpenLDAP ACLs are tricky and highly depend on your existing ACLs since the order is important. Therefore, the following example may needs to be adjusted for your specific OpenLDAP setup!

`ldapmodify -Y EXTERNAL -H ldapi:///`:
```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0} to attrs=msLAPS-PasswordExpirationTime,msLAPS-Password,msLAPS-EncryptedPassword,msLAPS-EncryptedPasswordHistory,msLAPS-EncryptedDSRMPassword,msLAPS-EncryptedDSRMPasswordHistory,msLAPS-CurrentPasswordVersion
  by self write
  by group/groupOfNames/member=cn=LAPS-ADMINS,dc=example,dc=com read
  by * none
```

Since the setup is still not complex enough, when authenticating via Kerberos (GSSAPI), the username seen by OpenLDAP is in form of `uid=computername,[cn=example.com,]cn=gssapi,cn=auth` instead of the object's DN `cn=computername,ou=computer,dc=example,dc=com`. You can imagine that the previously configured ACL "[...] by self write" permission does not take effect because of this. For that, we need to configure an identity mapping as described in the [OpenLDAP docs](https://www.openldap.org/doc/admin26/sasl.html).

`ldapmodify -Y EXTERNAL -H ldapi:///`:
```
dn: cn=config
changetype: modify
add: olcAuthzRegexp
olcAuthzRegexp: {0}uid=(.+),cn=gssapi,cn=auth ldap:///dc=example,dc=com??one?(krbPrincipalName:caseIgnoreIA5Match:=$1\40EXAMPLE.COM)
```

Note that `\40` in the LDAP URI represents an escaped `@` char.

## 4. Join your Client Computer to the OpenLDAP
Create an object for your LAPS-managed computer in your LDAP directory, e.g. `cn=vm-VirtualBox,dc=example,dc=com`. Use our custom class `computer` for these objects. Then, create a Kerberos principal and keytab for this computer object:
```
$ kadmin.local
addprinc -randkey -x dn=cn=vm-VirtualBox,dc=example,dc=com VM-VIRTUALBOX$@EXAMPLE.COM
ktadd -k /tmp/krb5.keytab VM-VIRTUALBOX$@EXAMPLE.COM
```

This example uses an uppercase principal name with trailing dollar sign to follow the ugly Microsoft way. Of course you are free to use lowercase chars without dollar sign, but then you need to manually edit the "hostname" field in `/etc/laps-runner.json` on the LAPS managed computer.

Move the generated `/tmp/krb5.keytab` to `/etc/krb5.keytab` on the target LAPS managed computer. Restrict the access to the root user.

## 5. Execute the Runner
Adjust your LAPS Runner config as described in the Runner [README.md](../laps-runner/README.md) (set LDAP attributes, decide if Native LAPS should be used etc.).

And finally you can execute the runner on the managed computer and it will generate an admin password and store it in your OpenLDAP. Yay!
