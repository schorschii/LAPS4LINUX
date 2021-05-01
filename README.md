# LAPS4LINUX
Linux implementation of the Local Administrator Password Solution (LAPS) from Microsoft.

## CLI
```
$ ./laps-cli.py --search notebook01
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password: 
Connection: ldapserver01: user@example.com
Found:      CN=NOTEBOOK01,OU=NOTEBOOKS,DC=example,DC=com
Password:   abc123
Expiration: 132641316610000000 (2021-04-29 01:01:01)


$ ./laps-cli.py --show-all
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password: 
Connection: ldapserver01: user@example.com
NOTEBOOK01$ : abc123
NOTEBOOK02$ : 123abc
...


$ ./laps-cli.py --search notebook01 --set-expiry "2021-04-28 01:01:01"
LAPS4LINUX CLI v1.0.0
https://github.com/schorschii/laps4linux

🔑 Password: 
Connection: ldapserver01: user@example.com
Found:      CN=NOTEBOOK01,OU=NOTEBOOKS,DC=example,DC=com
Password:   abc123
Expiration: 132641316610000000 (2021-04-29 01:01:01)
New Expiration: 132640452610000000 (2021-04-28 01:01:01)
Expiration Date Changed Successfully.
```

## GUI
![screenshot](.github/screenshot.png)

