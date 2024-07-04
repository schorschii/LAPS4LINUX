# LAPS4LINUX Client
The management client enables administrators to view the current (decrypted) local admin passwords. It can be used from command line or as graphical application.

### Graphical User Interface (GUI)
![screenshot](../.github/screenshot.png)

### Command Line Interface (CLI)
```
$ laps-cli notebook01 --set-expiry "2021-04-28 01:01:01"
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password for »ldapuser«:
Connection:     ldapserver01: user@example.com
Found:          CN=NOTEBOOK01,OU=NOTEBOOKS,DC=example,DC=com
Password:       abc123
Expiration:     132641316610000000 (2021-04-29 01:01:01)
New Expiration: 132640452610000000 (2021-04-28 01:01:01)
Expiration Date Changed Successfully.


$ laps-cli "*"
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password for »ldapuser«:
Connection: ldapserver01: user@example.com
NOTEBOOK01$ : abc123
NOTEBOOK02$ : 123abc
...
```

### Installation
It is recommended to use the installation package provided on the [Github releases](https://github.com/schorschii/LAPS4LINUX/releases) page.

Manual installation in a Python venv:
```
# install available python modules globally to avoid duplicate install in venv
apt install python3-venv python3-pip python3-setuptools python3-qtpy python3-gssapi python3-dnspython python3-pycryptodome libkrb5-dev

python3 -m venv venv --system-site-packages
venv/bin/pip3 install .

venv/bin/laps-gui
venv/bin/laps-cli
```

### Configuration
By default, the clients will try to auto-discover your domain and LDAP servers via DNS. If this does not succeed, the client will ask you for this values and write it to the config file `~/.config/laps-client/settings.json`.

You can create a preset config file `/etc/laps-client.json` which will be loaded if `~/.config/laps-client/settings.json` does not exist. With this, you can distribute default settings (all relevant LDAP attributes, SSL on etc.) for new users.

<details>
  <summary>Configuration Values</summary>

  - `server`: Array of domain controllers with items like `{"address": "dc1.example.com", "port": 389, "ssl": false}`. Leave empty for DNS auto discovery.
  - `domain`: Your domain name (e.g. `example.com`). Leave empty for DNS auto discovery.
  - `ldap-query`: LDAP filter for getting the computer object, default: `(&(objectClass=computer)(cn=%1))`. `%1` is replaced by the computer name.
  - `use-starttls`: Boolean which indicates wheter to use StartTLS on unencrypted LDAP connections (requires valid server certificate).
  - `username`: The username for LDAP simple binds. For Microsoft AD, you need to append the domain (`user@example.com`). For OpenLDAP, you need to enter your user DN (`dn=user,dc=example,dc=com`).
  - `use-kerberos`: Boolean which indicates wheter to use Kerberos for LDAP bind before falling back to simple bind.
  - `ldap-attributes`: A dict of LDAP attributes to display. Dict key is the display name and the corresponding value is the LDAP attribute name. The dict value can also be a list of strings. Then, the first non-empty LDAP attribute will be displayed.
  - `ldap-attribute-password`: The LDAP attribute name which contains the admin password. The client will try to decrypt this value (in case of Native LAPS) and use it for Remmina connections. Can also be a list of strings.
  - `ldap-attribute-password-expiry`: The LDAP attribute name which contains the admin password expiration date. The client will write the updated expiration date into this attribute. Can also be a list of strings.
  - `ldap-attribute-password-history`: The LDAP attribute name which contains the admin password history. The client will try to decrypt this value (in case of Native LAPS) and use it to display the password history. Can also be a list of strings.
  - `connect-username`: The username which will be used for Remmina connections. May be modified by the client during the runtime since Native LAPS also stores username information.
</details>

If you want to view the DSRM password, simply put `msLAPS-EncryptedDSRMPassword` and `msLAPS-EncryptedDSRMPasswordHistory` into the `ldap-attributes` and `ldap-attribute-password`|`ldap-attribute-password-history` configuration.

### Kerberos Authentication
The client (both GUI and CLI) supports Kerberos authentication which means you can use the client without entering a password if you are logged in with a domain account and have a valid Kerberos ticket (for this, an SSL connection is required). If not, ldap3's "simple" authentication is used as fallback and the client will ask you for username and password. The Kerberos authentication attempt can be disabled by setting `use-kerberos` to `false` in the config file.

If you did not automatically received a Kerberos ticket on login, you can manually aquire a ticket via `kinit <username>@<DOMAIN.TLD>`.

### SSL Connection
By default, LAPS4LINUX (client and runner) will connect via LDAP on port 389 to your Active Directory and upgrade the connection via STARTTLS to an encrypted one. This means that your server needs a valid certificate and STARTTLS enabled. This behavior can be disabled by modifying the `use-starttls` in the config file, but it is strongly discouraged to disable it since sensitive data is transferred.

Alternatively, you can use LDAPS by editing the config file (`~/.config/laps-client/settings.json`): modify the server entry and set `ssl` to `true` and `port` to `636` (see example below). You can also configure multiple static LDAP servers in the config file.

### Domain Forest Searches
If you are managing multiple domains, you probably want to search for a computer in all domains. Please use the global catalog for this by setting the option `gc-port` in the configuration file of all servers, e.g. to `3268` (LDAP) or `3269` (LDAPS).

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

### Remote Access
On Linux, the GUI allows you to directly open RDP or SSH connections via Remmina from the menu. Please make sure you have installed the latest Remmina with RDP and SSH extensions. You can change the username which is used for the connection in the client config (`"connect-username": "administrator"`).

<details>
<summary>Flatpak Remmina</summary>

If you use Remmina installed via Flatpak, you need to create the following wrapper script which calls the Flatpak version of remmina. Do not forget to make it executable.

```
*** /usr/local/bin/remmina ***

#!/bin/bash
flatpak run org.remmina.Remmina $@
```
</details>

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
