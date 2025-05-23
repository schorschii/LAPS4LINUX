__title__     = 'LAPS4LINUX'
__author__    = 'Georg Sieber'
__copyright__ = '© 2021-2024'
__license__   = 'GPL-3.0'
__version__   = '1.12.1'
__website__   = 'https://github.com/schorschii/LAPS4LINUX'

__all__ = [__author__, __license__, __version__]



import os, sys
import getpass


if 'darwin' in sys.platform.lower():
	# set OpenSSL path to macOS defaults
	# (Github Runner sets this to /usr/local/etc/openssl@1.1/ which does not exist in plain macOS installations)
	os.environ['SSL_CERT_FILE'] = '/private/etc/ssl/cert.pem'
	os.environ['SSL_CERT_DIR']  = '/private/etc/ssl/certs'
	# system CA certs debugging
	#import ssl; print(ssl.get_default_verify_paths())
	#ctx = ssl.SSLContext(); ctx.load_default_certs(); print(ctx.get_ca_certs())

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
