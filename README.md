# LAPS4LINUX
Linux implementation of the Local Administrator Password Solution (LAPS) from Microsoft.

## Legacy and Native LAPS
Microsoft introducted the new "Native LAPS" in 2023. In contrast to Legacy LAPS, the new version uses different LDAP attributes and has the option to store the password encrypted in the LDAP directory. LAPS4LINUX supports both versions and you can switch between them by simply adjusting your configuration. Encrypted passwords are currently supported only within the client, not within the runner.

LAPS4LINUX uses the Native LAPS attributes as default. To upgrade to Native LAPS from a previous LAPS4LINUX version, please update your client and runner config file:

<details>
<summary>Legacy LAPS</summary>

```
.....
"native-laps": false,
"ldap-attribute-password": "ms-Mcs-AdmPwd",
"ldap-attribute-password-expiry": "ms-Mcs-AdmPwdExpirationTime",
"ldap-attributes": {
    "Administrator Password": "ms-Mcs-AdmPwd",
    "Password Expiration Date": "ms-Mcs-AdmPwdExpirationTime"
}
.....
```
</details>

<details>
<summary>Native LAPS (not encrypted)</summary>

```
.....
"native-laps": true,
"ldap-attribute-password": "msLAPS-Password",
"ldap-attribute-password-expiry": "msLAPS-PasswordExpirationTime",
"ldap-attributes": {
    "Administrator Password": "msLAPS-Password",
    "Password Expiration Date": "msLAPS-PasswordExpirationTime"
}
.....
```
</details>

<details>
<summary>Native LAPS (encrypted, LAPS client only)</summary>

Please note: only SID security descriptors are supported (e.g. `S-1-5-21-2185496602-3367037166-1388177638-1103`). Do not use group names (`DOMAIN\groupname`).
```
.....
"native-laps": true,
"ldap-attribute-password": "msLAPS-EncryptedPassword",
"ldap-attribute-password-expiry": "msLAPS-PasswordExpirationTime",
"ldap-attribute-password-history": "msLAPS-EncryptedPasswordHistory",
"ldap-attributes": {
    "Decrypted Administrator Password": "msLAPS-EncryptedPassword",
    "Password Expiration Date": "msLAPS-PasswordExpirationTime",
    "Administrator Password History": "msLAPS-EncryptedPasswordHistory"
}
.....
```
</details>

## Management Client
### Graphical User Interface (GUI)
![screenshot](.github/screenshot.png)

### Command Line Interface (CLI)
```
$ ./laps-cli.py notebook01 --set-expiry "2021-04-28 01:01:01"
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password for »ldapuser«:
Connection:     ldapserver01: user@example.com
Found:          CN=NOTEBOOK01,OU=NOTEBOOKS,DC=example,DC=com
Password:       abc123
Expiration:     132641316610000000 (2021-04-29 01:01:01)
New Expiration: 132640452610000000 (2021-04-28 01:01:01)
Expiration Date Changed Successfully.


$ ./laps-cli.py "*"
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password for »ldapuser«:
Connection: ldapserver01: user@example.com
NOTEBOOK01$ : abc123
NOTEBOOK02$ : 123abc
...
```

### Configuration
By default, the clients will try to auto-discover your domain and LDAP servers via DNS. If this does not succeed, the client will ask you for this values and write it to the config file `~/.config/laps-client/settings.json`.

### Kerberos Authentication
The client (both GUI and CLI) supports Kerberos authentication which means that you can use the client without entering a password if you are logged in with a domain account and have a valid Kerberos ticket (for this, an SSL connection is required). If not, ldap3's "simple" authentication is used as fallback and the client will ask you for username and password. The Kerberos authentication attempt can be disabled by setting `use-kerberos` to `false` in the config file.

If you did not automatically received a Kerberos ticket on login, you can manually aquire a ticket via `kinit <username>@<DOMAIN.TLD>`.

### SSL Connection
By default, LAPS4LINUX (client and runner) will connect via LDAP on port 389 to your Active Directory and upgrade the connection via STARTTLS to an encrypted one. This means that your server needs a valid certificate and STARTTLS enabled. This behavior can be disabled by modifying the `use-starttls` in the config file, but it is strongly discouraged to disable it since sensitive data is transferred.

Alternatively, you can use LDAPS by editing the config file (`~/.config/laps-client/settings.json`): modify the server entry and set `ssl` to `true` and `port` to `636` (see example below). You can also configure multiple static LDAP servers in the config file.

### Domain Forest Searches
If you are managing multiple domains, you probably want to search for a computer in all domains. Please use the global catalog for this. This means that you need to set the option `gc-port` in the configuration file of all servers, e.g. to `3268` (LDAP) or `3269` (LDAPS).

<details>
<summary>Example</summary>

```
{
    "server": [
        {
            "address": "dc.example.com",
            "port": 636,
            "gc-port": 3269,
            "ssl": true
        },
        .....
    ],
    .....
}
```
</details>

Since the global catalog is read only, LAPS4LINUX will switch to "normal" LDAP(S) port when you want to change the password expiry date. That's why, the `port` option is still required even if a `gc-port` is given!

### Query Additional Attributes (Customization)
LAPS4LINUX allows you to query additional attributes besides the admin password which might be of interest for you. For that, just edit the config file `~/.config/laps-client/settings.json` and enter the additional LDAP attributes you'd like to query into the settings array `"ldap-attributes"`.

The setting `ldap-attribute-password-expiry` defines in which LDAP attribute the date will be written when selecting a new expiration date. If you like, you can hide the "Set Expiration" button by entering an empty string for this setting.

With the setting `ldap-attribute-password` you define which LDAP attribute is considered as the admin password (for usage with the Remmina connect feature).

### Default Config File
You can create a preset config file `/etc/laps-client.json` which will be loaded if `~/.config/laps-client/settings.json` does not exist. With this, you can distribute default settings (all relevant LDAP attributes, SSL on etc.) for new users.

### Remote Access
On Linux, the GUI allows you to directly open RDP or SSH connections via Remmina from the menu. Please make sure you have installed the latest Remmina with RDP and SSH extensions. You can change the username which is used for the connection in the client config (`"connect-username": "administrator"`).

### Windows and macOS
The clients (GUI and CLI) are also executable under Windows and macOS. It's ported to Windows because of the additional features that the original LAPS GUI did not have (query custom attributes, OCO integration).

### `laps://` Protocol Scheme
The GUI supports the protocol scheme `laps://`, which means you can call the GUI like `laps-gui.py laps://HOSTNAME` to automatically search `HOSTNAME` after startup. This feature is mainly intended to use with the [OCO server](https://github.com/schorschii/OCO-Server) web frontend ("[COMPUTER_COMMANDS](https://github.com/schorschii/OCO-Server/blob/master/docs/Computers.md#client-commands)").

<details>
<summary>Linux</summary>

On Linux, you need to create file `/usr/share/applications/LAPS4LINUX-protocol-handler.desktop` with the following content and execute `update-desktop-database`.
```
[Desktop Entry]
Type=Application
Name=LAPS4LINUX Protocol Handler
Exec=/usr/bin/laps-gui %u
StartupNotify=false
MimeType=x-scheme-handler/laps;
NoDisplay=true
```
</details>

<details>
<summary>macOS</summary>

On macOS, the protocol handler is registered using the Info.plist file (setting "CFBundleURLTypes") in the .app directory.
Please use laps-gui.macos.spec with pyinstaller to automatically create an .app directory which registers itself for the laps:// protocol on first launch.
</details>

<details>
<summary>Windows</summary>

On Windows, you need to set the following registry values:
```
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\laps]
@="URL:LAPS"
"URL Protocol"=""

[HKEY_CLASSES_ROOT\laps\shell]

[HKEY_CLASSES_ROOT\laps\shell\open]

[HKEY_CLASSES_ROOT\laps\shell\open\command]
@="\"C:\\Program Files\\LAPS4WINDOWS\\laps-gui.exe\" %1"
```
</details>

## Runner
The runner is responsible for automatically changing the admin password of a Linux client and updating it in the LDAP directory. This assumes that Kerberos (`krb5-user`) is installed and that the machine is already joined to your domain using Samba's `net ads join`, PBIS' `domainjoin-cli join` or the `adcli join` command (recommended). `realm join` is also supported as it internally also uses adcli resp. Samba.

A detailed domain join guide is available [on my website](https://georg-sieber.de/?page=blog-linux-im-unternehmen) (attention: only in German).

The runner should be called periodically via cron. It decides by the expiration time stored in the LDAP directory when the password should be changed.
```
*** /etc/cron.hourly/laps-runner ***

#!/bin/sh
/usr/sbin/laps-runner --config /etc/laps-runner.json
```

Please configure the runner by editing the configuration file `/etc/laps-runner.json`. You can leave the server array empty if the runner should auto-discover your domain controllers by DNS SRV records.

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
