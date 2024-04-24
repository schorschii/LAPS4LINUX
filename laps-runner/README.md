# LAPS4LINUX Runner
The runner is responsible for automatically changing the admin password of a Linux client and updating it in the LDAP directory. This assumes that Kerberos (`krb5-user`) is installed and that the machine is already joined to your domain using Samba's `net ads join`, PBIS' `domainjoin-cli join` or the `adcli join` command (recommended). `realm join` is also supported as it internally also uses adcli resp. Samba.

A detailed domain join guide is available [on my website](https://georg-sieber.de/?page=blog-linux-im-unternehmen) (attention: only in German).

The runner should be called periodically via cron ([example](../assets/laps-runner.cron)). This does not mean that the password will be rotated every time the cron job runs - it decides by the expiration time stored in the LDAP directory when the password needs to be changed.

Please make sure that `usermod` (for changing the password in the local database) is in you crontab `$PATH` (this is the default in Debian and Ubuntu based systems, but may not in other distros).

### Installation
It is recommended to use the installation package provided on the [Github releases](https://github.com/schorschii/LAPS4LINUX/releases) page.

Manual installation in a Python venv:
```
# install available python modules globally to avoid duplicate install in venv
apt install python3-venv python3-pip python3-setuptools python3-gssapi python3-dnspython krb5-user libkrb5-dev

python3 -m venv venv --system-site-packages
venv/bin/pip3 install .

venv/bin/laps-runner
```

### Configuration
Please configure the runner by editing the configuration file `/etc/laps-runner.json`.

<details>
  <summary>Configuration Values</summary>

  - `server`: Array of domain controllers with items like `{"address": "dc1.example.com", "port": 389, "ssl": false}`. Leave empty for DNS auto discovery.
  - `domain`: Your domain name (e.g. `example.com`). Leave empty for DNS auto discovery.
  - `use-starttls`: Boolean which indicates wheter to use StartTLS on unencrypted LDAP connections (requires valid server certificate).
  - `client-keytab-file`: The Kerberos keytab file with the machine secret.
  - `cred-cache-file`: File where to store the kerberos ticket for the LDAP connection.
  - `native-laps`: `true` to store the password as JSON string in the LDAP attribute, as specified by Microsoft (Native LAPS). `false` to store it as plaintext (Legacy LAPS).
  - `security-descriptor`: The security descriptor (SID) for pasword encryption (Native LAPS only). Leave empty (set to `null`) to disable encryption. Important: if you enable encryption, you should also change `ldap-attribute-password` to `msLAPS-EncryptedPassword`!
  - `history-size`: The amount of password entries to keep in history. If not set or `0`, no password history will be written.
  - `ldap-attribute-password`: The LDAP attribute name where to store the generated password. Must be a string, not a list.
  - `ldap-attribute-password-history`: The LDAP attribute where to store the password history. Must be a multi-value text field. If empty, no password history will be written.
  - `ldap-attribute-password-expiry`: The LDAP attribute where to store the password expiration date. Must be a string, not a list.
  - `hostname`: The hostname used for Kerberos ticket creation. Leave empty to use the system's hostname.
  - `password-change-user`: The Linux user whose password should be rotated.
  - `password-days-valid`: The amount of days how long a password should be valid.
  - `password-length`: Determines how long a generated password should be.
  - `password-alphabet`: Determines the chars to use for password generation.

Important:
- If `native-laps` is `false`, you should set `ldap-attribute-password` to `ms-Mcs-AdmPwd` and `ldap-attribute-password-expiry` to `ms-Mcs-AdmPwdExpirationTime`.
- If If `native-laps` is `true` and `security-descriptor` not set or `null`, you should set `ldap-attribute-password` to `msLAPS-Password` and `ldap-attribute-password-expiry` to `msLAPS-PasswordExpirationTime`.
- If If `native-laps` is `true` and `security-descriptor` is set to a valid SID in your domain, you should set `ldap-attribute-password` to `msLAPS-EncryptedPassword` and `ldap-attribute-password-expiry` to `msLAPS-PasswordExpirationTime`.
- While it is technically possible to save the password history unencrypted, Microsoft did not designated this. By default, in Active Directory, the only password history attribute is `msLAPS-EncryptedPasswordHistory`. Therefore, you should only configure the runner to store a password history when using password encryption too.
</details>

You can call the runner with the `-f` parameter to force updating the password directly after installation. You should do this to check if the runner is working properly.

### Hostnames Longer Than 15 Characters
Computer objects in the Microsoft Active Directory can not be longer than 15 characters. If you join a computer with a longer hostname, it will be registered with a different "short name". You have to enter this short name in the config file (setting `hostname`) in order to make the Kerberos authentication work. You can find out the short name by inspecting your keytab: `sudo klist -k /etc/krb5.keytab`.

Set the `hostname` option to `null` (default) to use the system's normal host name.

### Troubleshooting
If the script throws an error like `kinit -k -c /tmp/laps.temp SERVER$ returned non-zero exit code 1`, please check what happens when you execute the following commands manually on the command line.
```
sudo kinit -k -c /tmp/laps.temp COMPUTERNAME$
sudo klist -c /tmp/laps.temp
```
Please replace COMPUTERNAME with your hostname, but do not forget the trailing dollar sign.

## Support
If you like LAPS4LINUX please consider making a donation using the sponsor button on [GitHub](https://github.com/schorschii/LAPS4LINUX) to support further development.

You can hire me for commercial support or adjustments for this project. Please [contact me](https://georg-sieber.de/?page=impressum) if you are interested.
