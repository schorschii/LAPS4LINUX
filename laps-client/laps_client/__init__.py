__title__     = 'LAPS4LINUX'
__author__    = 'Georg Sieber'
__copyright__ = '© 2021-2024'
__license__   = 'GPL-3.0'
__version__   = '1.10.4'
__website__   = 'https://github.com/schorschii/LAPS4LINUX'

__all__ = [__author__, __license__, __version__]



import getpass


def proposeUsername(domain):
	return getpass.getuser() + ('@'+domain if domain else '')

def compileServerUris(servers):
	uris = []
	for server in servers:
		uris.append(
			('ldaps://' if server['ssl'] else 'ldap://')
			+ str(server['address']) + ':' + str(server['port'])
		)
	return uris
