<img align="right" style="width:180px" src="assets/laps.png">

# LAPS4LINUX
Linux and macOS implementation of the Local Administrator Password Solution (LAPS) from Microsoft. The client is also executable under Windows and provides additional features (e.g. display additional LDAP values, directly start remote connections and it can be called with `laps://` protocol scheme parameter to directly start search).

LAPS in general is a system which periodically changes local admin passwords on domain computers and stores them (encrypted) in the LDAP directory (i.e. Active Directory), where domain administrators can decrypt and view them. This ensures that people who leave the company do not have access to local admin accounts anymore and that every local admin has a strong unique password set.

## Client
The management client enables administrators to view the current (decrypted) local admin passwords. It can be used from command line or as graphical application.

Read [README.md in the laps-client dir](laps-client/) for more information.

## Runner
The runner is responsible for periodically rotating the admin password of a Linux client and updating it in the LDAP directory.

Read [README.md in the laps-runner dir](laps-runner/) for more information.

## Support for both Legacy and Native LAPS
Microsoft introducted the new "Native LAPS" in 2023. In contrast to Legacy LAPS, the new version uses different LDAP attributes and has the option to store the password encrypted in the LDAP directory. LAPS4LINUX supports both versions out-of-the-box. The client will search for a password in the following order: Native LAPS encrypted, Native LAPS unencrypted, Legacy LAPS (unencrypted).

The runner can operate in Legacy or Native mode by switching the setting `native-laps` to `true` or `false`. In Native mode, the runner stores the password and username as JSON string in the LDAP attribute, as defined by Microsoft. In addition to that, when in Native mode, you can set `security-descriptor` to a valid SID in your domain and the runner will encrypt the password for this user/group. Please note: only SID security descriptors are supported (e.g. `S-1-5-21-2185496602-3367037166-1388177638-1103`), do not use group names (`DOMAIN\groupname`). If you enable encryption, you should also change `ldap-attribute-password` to `msLAPS-EncryptedPassword` to store the encrypted password in the designated LDAP attribute for compatibility with other Tools. Please have a look at the runner section below for more information.

For de-/encryption, the Python [dpapi-ng library](https://github.com/jborean93/dpapi-ng) is used.
