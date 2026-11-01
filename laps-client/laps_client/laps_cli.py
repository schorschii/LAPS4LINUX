#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .__init__ import __title__, __version__, __website__, __author__, __copyright__
from .__init__ import propose_username
from .filetime import dt_to_filetime, filetime_to_dt

from pathlib import Path
from os import path, makedirs, rename
from datetime import datetime
from dns import resolver, rdatatype
import dpapi_ng
import ldap3
import ssl
import getpass
import argparse
import json
import sys
import os


class LapsCli():
	PLATFORM          = sys.platform.lower()

	gc_mode_on = False
	server     = None
	connection = None
	tmp_dn     = ''

	cfg_preset_dir_windows = sys.path[0]
	cfg_preset_dir_unix    = '/etc'
	cfg_preset_file        = 'laps-client.json'
	cfg_preset_path        = (cfg_preset_dir_windows if sys.platform.lower()=='win32' else cfg_preset_dir_unix)+'/'+cfg_preset_file 

	cfg_dir             = str(Path.home())+'/.config/laps-client'
	cfg_path            = cfg_dir+'/settings.json'
	cfg_version         = 0
	cfg_use_kerberos    = True
	cfg_use_start_tls   = True
	cfg_server          = []
	cfg_domain          = None
	cfg_ldap_query      = '(&(objectClass=computer)(cn=%1))'
	cfg_username        = ''
	cfg_password        = ''
	cfg_ca_certs_file   = None
	cfg_tls_validate    = ssl.CERT_REQUIRED
	cfg_ldap_attributes = {
		'Operating System':               'operatingSystem',
		'Administrator Password':         ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd'],
		'Password Expiration Date':       ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'],
		'Administrator Password History': 'msLAPS-EncryptedPasswordHistory'
	}
	cfg_ldap_attribute_password         = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd']
	cfg_ldap_attribute_password_expiry  = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
	cfg_ldap_attribute_password_history = 'msLAPS-EncryptedPasswordHistory'


	def __init__(self, use_kerberos=None, qr_code=True):
		self.load_settings()
		if(use_kerberos != None): self.cfg_use_kerberos = use_kerberos
		self.cfg_qr_code = qr_code

		# show version information
		print(__title__ + ' CLI Client' +' v'+__version__)

	def get_attributes_as_dict(self):
		final_dict = {}
		if(isinstance(self.cfg_ldap_attributes, list)):
			for attribute in self.cfg_ldap_attributes:
				final_dict[attribute] = attribute
		elif(isinstance(self.cfg_ldap_attributes, dict)):
			for title, attribute in self.cfg_ldap_attributes.items():
				final_dict[str(title)] = attribute
		return final_dict

	def search_computer(self, computer_name):
		# check and escape input
		if computer_name.strip() == '': return
		search_all_computers = (computer_name=='*')
		if not search_all_computers:
			computer_name = ldap3.utils.conv.escape_filter_chars(computer_name)

		# ask for credentials and print connection details
		if not self.check_credentials_and_connect(): return
		if not search_all_computers:
			self.push_result('Connection', self.get_connection_string())

		try:
			# start LDAP search
			count = 0
			self.connection.search(
				search_base = self.create_ldap_base(self.connection),
				search_filter = self.cfg_ldap_query.replace('%1', computer_name),
				attributes = []
			)
			for entry in self.connection.entries:
				count += 1
				self.push_result('Found', entry.entry_dn)
				self.tmp_dn = entry.entry_dn
				self.query_attributes(search_all_computers)
				self.print_result(search_all_computers)

			# no result found
			if count == 0:
				self.tmp_dn = ''
				eprint('No result for query »'+computer_name+'«')
		except Exception as e:
			import traceback
			print(traceback.format_exc())
			# display error
			eprint('Error:', str(e))
			# reset connection
			self.server = None
			self.connection = None
		self.dct_result = []
		print()

	def set_expiry(self, new_expiration_date_time_string):
		# check if dn of target computer object is known
		if self.tmp_dn.strip() == '': return

		try:
			if isinstance(self.cfg_ldap_attribute_password_expiry, list) and len(self.cfg_ldap_attribute_password_expiry) > 0:
				attribute_expiration_date = self.cfg_ldap_attribute_password_expiry[0]
			else:
				attribute_expiration_date = str(self.cfg_ldap_attribute_password_expiry)

			# calc new time
			new_expiration_date = datetime.strptime(new_expiration_date_time_string, '%Y-%m-%d %H:%M:%S')
			new_expiration_date_time = dt_to_filetime(new_expiration_date)
			self.push_result('New Expiration', str(new_expiration_date_time)+' ('+str(new_expiration_date)+')')

			# start LDAP modify
			self.connection.modify(self.tmp_dn, { attribute_expiration_date: [(ldap3.MODIFY_REPLACE, [str(new_expiration_date_time)])] })
			if self.connection.result['result'] == 0:
				print('Expiration Date Changed Successfully.')
			else:
				print('Unable to change expiration date. '+str(self.connection.result['message']))

		except Exception as e:
			# display error
			eprint('Error:', str(e))
			# reset connection
			self.server = None
			self.connection = None

	def query_attributes(self, suppress_qr_code=True):
		if(not self.reconnect_for_attribute_query()):
			return

		# start LDAP search
		self.connection.search(
			search_base = self.tmp_dn,
			search_filter = '(objectClass=*)',
			attributes = ldap3.ALL_ATTRIBUTES
		)
		# display result
		for entry in self.connection.entries:
			# we are looking at the main computer object
			if(entry.entry_dn == self.tmp_dn):
				# evaluate attributes of interest
				for title, attribute in self.get_attributes_as_dict().items():
					if(attribute[:4] == 'sub:'): continue
					value = None
					if(isinstance(attribute, list)):
						for _attribute in attribute:
							# use first non-empty attribute
							if(str(_attribute) in entry and entry[str(_attribute)]):
								value = entry[str(_attribute)]
								attribute = str(_attribute)
								break
					elif(str(attribute) in entry):
						value = entry[str(attribute)]

					# handle non-existing attributes
					if(value == None):
						self.push_result(str(title), '')

					# if this is the password attribute -> try to parse Native LAPS format
					elif(len(value) > 0 and
						(str(attribute) == self.cfg_ldap_attribute_password or (isinstance(self.cfg_ldap_attribute_password, list) and str(attribute) in self.cfg_ldap_attribute_password))
					):
						password, username, timestamp = self.parse_laps_value(value.values[0])
						if(not username or not password):
							self.push_result(str(title), password)
						else:
							self.push_result(str(title), password+'  ('+username+')  ('+timestamp+')')

						if(self.cfg_qr_code and not suppress_qr_code):
							self.show_code(password)

					# if this is the encrypted password history attribute -> try to parse Native LAPS format
					elif(len(value) > 0 and
						(str(attribute) == self.cfg_ldap_attribute_password_history or (isinstance(self.cfg_ldap_attribute_password_history, list) and str(attribute) in self.cfg_ldap_attribute_password_history))
					):
						for _value in value.values:
							password, username, timestamp = self.parse_laps_value(_value)
							if(not username or not password):
								self.push_result(str(title), password)
							else:
								self.push_result(str(title), password+'  ('+username+')  ('+timestamp+')')

					# if this is the expiry date attribute -> format date
					elif(str(attribute) == self.cfg_ldap_attribute_password_expiry or (isinstance(self.cfg_ldap_attribute_password_expiry, list) and str(attribute) in self.cfg_ldap_attribute_password_expiry)):
						try:
							self.push_result(str(title), str(value)+' ('+str(filetime_to_dt( int(str(value)) ))+')')
						except Exception as e:
							eprint('Error:', str(e))
							self.push_result(str(title), str(value))

					# display raw value
					else:
						self.push_result(str(title), str(value))

			# we are looking at a sub-item of the computer object, e.g. a BitLocker recovery key
			else:
				for title, attribute in self.get_attributes_as_dict().items():
					if(attribute[:4] != 'sub:'): continue
					subattribute = str(attribute[4:])
					if(subattribute in entry):
						self.push_result(str(title), str(entry[subattribute]))

	dpapi_cache = dpapi_ng.KeyCache()
	def decrypt_password(self, blob):
		last_decryption_error = ''
		for server in self.server.servers:
			try:
				kerberos_auth = (self.cfg_username=='' or self.cfg_password=='')
				decrypted = dpapi_ng.ncrypt_unprotect_secret(
					blob, server = server.host,
					username = None if kerberos_auth else self.cfg_username,
					password = None if kerberos_auth else self.cfg_password,
					cache = self.dpapi_cache
				)
				return decrypted.decode('utf-8').replace("\x00", "")
			except Exception as e:
				if(last_decryption_error != str(e)):
					eprint('Decryption Error:', str(e))
					last_decryption_error = str(e)

	def parse_laps_value(self, ldap_value):
		try:
			# if type is bytes -> try to decrypt
			if(type(ldap_value) is bytes):
				decrypted_value = self.decrypt_password(ldap_value[16:])
				if(decrypted_value): ldap_value = decrypted_value

			# parse Native LAPS JSON
			json_dict = json.loads(ldap_value)
			if(not 'n' in json_dict or not 'p' in json_dict or not 't' in json_dict):
				raise Exception('Invalid LAPS JSON')
			return json_dict['p'], json_dict['n'], str(filetime_to_dt( int(json_dict['t'], 16) ))

		except Exception as e:
			# directly use LDAP value as password (Legacy LAPS)
			return ldap_value, None, None

	dct_result = []
	def push_result(self, attribute, value):
		self.dct_result.append({'title':attribute, 'value':value})

	def print_result(self, tsv=False):
		if(tsv):
			display_values = []
			for attribute_value in self.dct_result:
				display_values.append(attribute_value['value'])
			print("\t".join(display_values))
		else:
			max_title_len = 1
			for attribute_value in self.dct_result:
				max_title_len = max(max_title_len, len(attribute_value['title']))
			for attribute_value in self.dct_result:
				print((attribute_value['title']+':').ljust(max_title_len+2)+str(attribute_value['value']))
		self.dct_result = []

	def show_code(self, code):
		try:
			import qrcode
			qr = qrcode.QRCode()
			qr.add_data(code)
			qr.print_ascii()
		except Exception as e:
			eprint('Unable to print QR code:', e)

	def check_credentials_and_connect(self):
		# ask for server address and domain name if not already set via config file
		if(self.cfg_domain == None):
			item = input('♕ Domain Name (e.g. example.com, leave empty to try auto discovery): ')
			if item != None:
				self.cfg_domain = item
				self.server = None
		if(len(self.cfg_server) == 0):
			# query domain controllers by dns lookup
			search_domain = '.'+self.cfg_domain if self.cfg_domain!='' else ''
			try:
				res = resolver.resolve(qname='_ldap._tcp'+search_domain, rdtype=rdatatype.SRV, lifetime=10, search=True)
				for srv in res.rrset:
					server_entry = {
						# strip the trailing . from the dns resolver for certificate verification reasons.
						'address': str(srv.target).rstrip('.'),
						'port': srv.port,
						'ssl': (srv.port == 636),
						'auto-discovered': True
					}
					print('DNS auto discovery found server: '+json.dumps(server_entry, indent=2))
					self.cfg_server.append(server_entry)
			except Exception as e:
				eprint('DNS auto discovery failed:', str(e))
			# ask user to enter server names if auto discovery was not successful
			if(len(self.cfg_server) == 0):
				item = input('💻 LDAP Server Address: ')
				if item and item.strip() != '':
					self.cfg_server.append({
						'address': item,
						'port': 389,
						'ssl': False
					})
					self.server = None
		self.save_settings()

		# disable STARTTLS if SSL is used (otherwise, ldap3 will try to do STARTTLS on port 636)
		if(len(self.cfg_server) > 0 and self.cfg_server[0]['ssl'] == True):
			self.cfg_use_start_tls = False

		# establish server connection
		if(self.server == None):
			try:
				tls_settings = ldap3.Tls(validate=self.cfg_tls_validate, ca_certs_file=self.cfg_ca_certs_file)
				server_array = []
				for server in self.cfg_server:
					port = server['port']
					if('gc-port' in server):
						port = server['gc-port']
						self.gc_mode_on = True
					server_array.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], tls=tls_settings, get_info=ldap3.ALL))
				self.server = ldap3.ServerPool(server_array, ldap3.FIRST, active=2, exhaust=True)
			except Exception as e:
				eprint('Error connecting to LDAP server:', str(e))
				return False

		# try to bind to server via Kerberos
		try:
			if(self.cfg_use_kerberos):
				self.connection = ldap3.Connection(
					self.server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
				)
				if(self.cfg_use_start_tls): self.connection.start_tls()
				return True # return if connection created successfully
		except Exception as e:
			eprint('Unable to connect via Kerberos:', str(e))
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				raise Exception('Unable to connect to any of your LDAP servers')

		# ask for username and password for SIMPLE bind
		if(self.cfg_username == ''):
			default_username = propose_username(self.cfg_domain)
			item = input('👤 Username ['+default_username+']: ') or default_username
			if item and item.strip() != '':
				self.cfg_username = item
				self.connection = None
			else: return False
		if(self.cfg_password == ''):
			item = getpass.getpass('🔑 Password for »'+self.cfg_username+'«: ')
			if item and item.strip() != '':
				self.cfg_password = item
				self.connection = None
			else: return False
		self.save_settings()

		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(
				self.server,
				user=self.cfg_username,
				password=self.cfg_password,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
			)
			if(self.cfg_use_start_tls): self.connection.start_tls()
			print('') # separate user input from results by newline
		except Exception as e:
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				raise Exception('Unable to connect to any of your LDAP servers')
			self.cfg_username = ''
			self.cfg_password = ''
			eprint('Error binding to LDAP server:', str(e))
			return False

		return True

	def reconnect_for_attribute_query(self):
		# global catalog was not used for search - we can use the same connection for attribute query
		if(not self.gc_mode_on): return True
		# global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
		# -> that's why we need to establish a new connection to the "normal" LDAP port
		# LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
		tls_settings = ldap3.Tls(validate=self.cfg_tls_validate, ca_certs_file=self.cfg_ca_certs_file)
		server_array = []
		for server in self.cfg_server:
			server_array.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], tls=tls_settings, get_info=ldap3.ALL))
		server = ldap3.ServerPool(server_array, ldap3.FIRST, active=True, exhaust=True)
		# try to bind to server via Kerberos
		try:
			if(self.cfg_use_kerberos):
				self.connection = ldap3.Connection(server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
				)
				if(self.cfg_use_start_tls): self.connection.start_tls()
				return True
		except Exception as e:
			eprint('Unable to connect via Kerberos:', str(e))
		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(server,
				user=self.cfg_username,
				password=self.cfg_password,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
			)
			if(self.cfg_use_start_tls): self.connection.start_tls()
			return True
		except Exception as e:
			eprint('Error binding to LDAP server:', str(e))
			return False

	def create_ldap_base(self, conn):
		if self.cfg_domain:
			# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
			search_base = ''
			base = self.cfg_domain.split('.')
			for b in base:
				search_base += 'DC=' + b + ','
			return search_base[:-1]
		elif conn.server.info and 'defaultNamingContext' in conn.server.info.raw:
			return conn.server.info.raw['defaultNamingContext'][0].decode('utf-8')
		else:
			raise Exception('Could not create LDAP search base: reading defaultNamingContext from LDAP directory failed and no domain given.')

	def get_connection_string(self):
		return str(self.connection.server.host)+' User:'+str(self.connection.user)

	def load_settings(self):
		if(not path.isdir(self.cfg_dir)):
			makedirs(self.cfg_dir, exist_ok=True)
		# protect temporary .remmina file by limiting access to our config folder
		if(self.PLATFORM == 'linux'): os.chmod(self.cfg_dir, 0o700)

		dct_preset_settings = {}
		dct_user_settings = {}
		cfg_json = {}

		try:
			if(path.isfile(self.cfg_path)):
				with open(self.cfg_path) as f:
					dct_user_settings = json.load(f)
					cfg_json = dct_user_settings
			if(path.isfile(self.cfg_preset_path)):
				with open(self.cfg_preset_path) as f:
					dct_preset_settings = json.load(f)
					# use preset config if version is higher or user settings are empty
					if(dct_preset_settings.get('version', 0) > dct_user_settings.get('version', 0)
					or dct_user_settings == {}):
						cfg_json = dct_preset_settings

			self.cfg_version = cfg_json.get('version', self.cfg_version)
			self.cfg_use_kerberos = cfg_json.get('use-kerberos', self.cfg_use_kerberos)
			self.cfg_use_start_tls = cfg_json.get('use-starttls', self.cfg_use_start_tls)
			self.cfg_server = cfg_json.get('server', self.cfg_server)
			self.cfg_domain = cfg_json.get('domain', self.cfg_domain)
			self.cfg_ldap_query = cfg_json.get('ldap-query', self.cfg_ldap_query)
			self.cfg_username = cfg_json.get('username', self.cfg_username)
			self.cfg_ca_certs_file = cfg_json.get('ca-certs-file', self.cfg_ca_certs_file)
			self.cfg_tls_validate = cfg_json.get('tls-validate', self.cfg_tls_validate)
			self.cfg_ldap_attribute_password = cfg_json.get('ldap-attribute-password', self.cfg_ldap_attribute_password)
			self.cfg_ldap_attribute_password_expiry = cfg_json.get('ldap-attribute-password-expiry', self.cfg_ldap_attribute_password_expiry)
			self.cfg_ldap_attribute_password_history = cfg_json.get('ldap-attribute-password-history', self.cfg_ldap_attribute_password_history)
			tmp_ldap_attributes = cfg_json.get('ldap-attributes', self.cfg_ldap_attributes)
			if(isinstance(tmp_ldap_attributes, list) or isinstance(tmp_ldap_attributes, dict)):
				self.cfg_ldap_attributes = tmp_ldap_attributes
		except Exception as e:
			eprint('Error loading settings file:', str(e))

	def save_settings(self):
		try:
			# do not save auto-discovered servers to config - should be queried every time
			save_servers = []
			for server in self.cfg_server:
				if not server.get('auto-discovered', False):
					save_servers.append(server)

			with open(self.cfg_path, 'w') as json_file:
				json.dump({
					'version': self.cfg_version,
					'use-kerberos': self.cfg_use_kerberos,
					'use-starttls': self.cfg_use_start_tls,
					'server': save_servers,
					'domain': self.cfg_domain,
					'ldap-query': self.cfg_ldap_query,
					'username': self.cfg_username,
					'ca-certs-file': self.cfg_ca_certs_file,
					'tls-validate': self.cfg_tls_validate,
					'ldap-attribute-password': self.cfg_ldap_attribute_password,
					'ldap-attribute-password-expiry': self.cfg_ldap_attribute_password_expiry,
					'ldap-attribute-password-history': self.cfg_ldap_attribute_password_history,
					'ldap-attributes': self.cfg_ldap_attributes
				}, json_file, indent=4)
		except Exception as e:
			eprint('Error saving settings file:', str(e))

def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)

def main():
	parser = argparse.ArgumentParser(
		description='If you like LAPS4LINUX please do not forget to give the repository a star ('+__website__+').',
		epilog=__copyright__+' '+__author__+' - https://georg-sieber.de'
	)
	parser.add_argument('search', default=None, nargs='*', metavar='COMPUTERNAME', help='Search for this computer(s) and display the admin password. Use "*" to display all computer passwords found in LDAP directory. If you omit this parameter, the interactive shell will be started, which allows you to do multiple queries in one session.')
	parser.add_argument('-e', '--set-expiry', default=None, metavar='"2020-01-01 00:00:00"', help='Set new expiration date for computer found by search string.')
	parser.add_argument('-K', '--no-kerberos', action='store_true', help='Do not use Kerberos authentication if available, ask for LDAP simple bind credentials.')
	parser.add_argument('-QR', '--no-qr', action='store_true', help='Do not use Kerberos authentication if available, ask for LDAP simple bind credentials.')
	parser.add_argument('--version', action='store_true', help='Print version and exit.')
	args = parser.parse_args()

	cli = LapsCli(
		False if args.no_kerberos==True else None,
		not args.no_qr
	)

	if(args.version):
		return

	# do LDAP search by command line arguments
	if(args.search):
		valid_searches = 0
		for term in args.search:
			if(term.strip() == '*'):
				cli.search_computer('*')
				return

			if(term.strip() != ''):
				valid_searches += 1
				cli.search_computer(term.strip())
				if(args.set_expiry and args.set_expiry.strip() != ''):
					cli.set_expiry(args.set_expiry.strip())

		# if at least one computername was given, we do not start the interactive shell
		if(valid_searches > 0): return

	# do LDAP search by interactive shell input
	print('')
	print('Welcome to interactive shell. Please enter a computer name to search for.')
	print('Parameter --help provides more information.')
	while True:
		# get keyboard input
		cmd = input('>> ')
		if(cmd == 'exit' or cmd == 'quit'):
			return
		else:
			cli.search_computer(cmd.strip())

if __name__ == '__main__':
	main()
