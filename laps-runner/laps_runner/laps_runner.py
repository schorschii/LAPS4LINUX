#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from . import __title__, __version__, __website__, __author__, __copyright__
from .filetime import dt_to_filetime, filetime_to_dt

from pathlib import Path
from typing import Any
from os import path
from datetime import datetime, timedelta, timezone
from dns import resolver, rdatatype
from shutil import which
from pid import PidFile, PidFileAlreadyLockedError, PidFileAlreadyRunningError
from passlib.context import CryptContext
import time
import struct
import ssl
import ldap3
import subprocess
import secrets
import string
import socket
import getpass
import argparse
import json
import sys, os
import logging
import logging.handlers
import traceback


class LapsRunner():
	server: ldap3.ServerPool | None     = None
	connection: ldap3.Connection | None = None
	logger: logging.Logger

	cfg_path             = '/etc/laps-runner.json'

	cfg_cred_cache_file              = '/tmp/laps.temp'
	cfg_client_keytab_file           = '/etc/krb5.keytab'
	cfg_use_start_tls                = True
	cfg_ca_certs_file: str | None    = None
	cfg_tls_validate                 = ssl.CERT_REQUIRED
	cfg_server: list[dict[str, Any]] = []
	cfg_domain                       = ''
	cfg_ldap_query                   = '(&(objectClass=computer)(cn=%1))'

	cfg_hostname: str | None      = None
	cfg_username                  = 'root' # the user, whose password should be changed
	cfg_days_valid                = 30 # how long the new password should be valid
	cfg_length                    = 15 # the generated password length
	cfg_alphabet: str | list[str] = string.ascii_letters+string.digits+string.punctuation # allowed chars for the new password

	cfg_use_native_laps_attribute_schema = True
	cfg_security_descriptor: str | None  = None
	cfg_history_size                     = 0 # disabled by default because encryption is disabled by default
	cfg_ldap_attribute_password          = 'msLAPS-Password'
	cfg_ldap_attribute_password_history  = 'msLAPS-EncryptedPasswordHistory'
	cfg_ldap_attribute_password_expiry   = 'msLAPS-PasswordExpirationTime'

	cfg_pam_services: list[str] = [] # PAM_SERVICE filter
	cfg_pam_grace_period = 0  # timeout in seconds to wait before changing the password after logout

	cfg_hooks: object = {} # validated at use, comes straight from the config file

	tmp_dn                           = ''
	tmp_password: str | bytes | None = None
	tmp_expiry                       = ''
	tmp_expiry_date: datetime        = datetime.fromtimestamp(0, timezone.utc)

	def __init__(self, *args: Any, **kwargs: Any) -> None:
		# init logger
		self.logger = logging.getLogger('LAPS4LINUX')
		self.logger.setLevel(logging.DEBUG)
		self.logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))

		# show note
		print(__title__ + ' Runner' +' v'+__version__)
		print('If you like LAPS4LINUX please do not forget to give the repository a star ('+__website__+').')
		print('')

	def get_hostname(self) -> str:
		if(self.cfg_hostname == None or self.cfg_hostname.strip() == ''):
			return socket.gethostname().split('.', 1)[0].upper()
		else:
			return self.cfg_hostname.strip().upper()

	def prepare_environment(self) -> dict[str, str]:
		# restore library search path for subprocess (modified by PyInstaller)
		# see https://pyinstaller.org/en/v6.9.0/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application
		sub_env = os.environ.copy()
		if('LD_LIBRARY_PATH_ORIG' in sub_env):
			sub_env['LD_LIBRARY_PATH'] = sub_env['LD_LIBRARY_PATH_ORIG']
		elif('LD_LIBRARY_PATH' in sub_env):
			del sub_env['LD_LIBRARY_PATH']
		return sub_env

	def init_kerberos(self) -> None:
		# query new kerberos ticket
		cmd = ['kinit', '-k', '-c', self.cfg_cred_cache_file, self.get_hostname()+'$']
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, env=self.prepare_environment())
		if res.returncode != 0: raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def connect_to_server(self) -> None:
		# set environment variables for kerberos operations
		os.environ['KRB5CCNAME'] = self.cfg_cred_cache_file
		os.environ['KRB5_CLIENT_KTNAME'] = self.cfg_client_keytab_file

		# set TLS options
		tlssettings = ldap3.Tls(
			validate=self.cfg_tls_validate,
			ca_certs_file=self.cfg_ca_certs_file
		)

		# connect to server with kerberos ticket
		server_array: list[ldap3.Server] = []
		if(len(self.cfg_server) == 0):
			# query domain controllers by dns lookup
			search_domain = '.'+self.cfg_domain if self.cfg_domain!='' else ''
			res = resolver.resolve(qname=f'_ldap._tcp'+search_domain, rdtype=rdatatype.SRV, lifetime=10, search=True)

			for srv in res:
				if(self.cfg_use_start_tls):
					# strip the trailing . from the dns resolver for certificate verification reasons.
					server_array.append(ldap3.Server(host=str(srv.target).rstrip('.'), port=389, tls=tlssettings, get_info=ldap3.ALL))
				else:
					server_array.append(ldap3.Server(host=str(srv.target).rstrip('.'), port=636, use_ssl=True, tls=tlssettings, get_info=ldap3.ALL))
		else:
			# use servers given in config file
			for server in self.cfg_server:
				server_array.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], tls=tlssettings, get_info=ldap3.ALL))
		self.server = ldap3.ServerPool(server_array, ldap3.ROUND_ROBIN, active=2, exhaust=True)
		self.connection = ldap3.Connection(
			self.server,
			version=3,
			authentication=ldap3.SASL,
			sasl_mechanism=ldap3.GSSAPI,
			auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
		)
		print('Connected as: '+self.get_connection_string())

	def search_computer(self) -> bool:
		if self.connection == None: raise Exception('No connection established')

		# check and escape input
		computer_name = ldap3.utils.conv.escape_filter_chars(self.get_hostname())

		# start query
		self.connection.search(
			search_base = self.create_ldap_base(self.connection),
			search_filter = self.cfg_ldap_query.replace('%1', computer_name),
			attributes = ldap3.ALL_ATTRIBUTES
		)
		for entry in self.connection.entries:
			# display result
			self.tmp_dn = entry.entry_dn
			try:
				self.tmp_password = entry[self.cfg_ldap_attribute_password][0]
			except Exception:
				pass
			try:
				self.tmp_expiry = str(entry[self.cfg_ldap_attribute_password_expiry])
			except Exception:
				pass
			try:
				# date conversion will fail if there is no previous expiration time saved
				self.tmp_expiry_date = filetime_to_dt( int(str(entry[self.cfg_ldap_attribute_password_expiry])) )
			except Exception as e:
				print('Unable to parse date '+str(self.tmp_expiry)+' - assuming that no expiration date is set.')
				self.tmp_expiry_date = datetime.fromtimestamp(0, timezone.utc)
			return True

		# no result found
		raise Exception('No Result For: '+computer_name)

	def update_password(self) -> None:
		# check if usermod is in PATH
		if(which('usermod') is None): raise Exception('usermod is not in PATH')

		# cache old password hash
		try:
			old_password_hashed = get_current_password_hash(self.cfg_username)
		except:
			self.logger.error('Error occurred during creation of a failsafe backup. Passwords left untouched.')
			raise

		# generate new values
		new_password = self.generate_password()
		new_password_hashed = CryptContext(schemes=['sha512_crypt']).hash(new_password)
		new_expiration_date = datetime.now().astimezone(timezone.utc) + timedelta(days=self.cfg_days_valid)

		# update password in local database
		self.update_local_password(self.cfg_username, new_password_hashed)

		print('Password of user "'+self.cfg_username+'" successfully changed in local database')
		self.logger.debug(__title__+': Changed password of user "'+self.cfg_username+'" in local database')

		# update in directory
		try:
			self.set_password_and_expiry(new_password, new_expiration_date)
		except:
			self.logger.error('Error occurred when attempting to change password on directory server.')

			self.update_local_password(self.cfg_username, old_password_hashed)

			print('Password of user "'+self.cfg_username+'" successfully reverted in local database')
			self.logger.debug(__title__+': Reverted password of user "'+self.cfg_username+'" in local database')

			raise

		# execute hooks
		if(not isinstance(self.cfg_hooks, dict)): return
		for hook_name, hook_args in self.cfg_hooks.items():
			if(not isinstance(hook_args, list)): continue
			replacements = {'$PASSWORD$':new_password, '$USERNAME$':self.cfg_username}
			cmd: list[str] = [replacements[n] if n in replacements else n for n in hook_args]
			res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, env=self.prepare_environment())
			if res.returncode == 0:
				print('Hook "'+hook_name+'" successfully executed')
				self.logger.debug(__title__+': Hook "'+hook_name+'" successfully executed')
			else:
				print('Error: hook "'+hook_name+'" returned non-zero exit code '+str(res.returncode))
				self.logger.debug(__title__+': '+'Error: hook "'+hook_name+'" returned non-zero exit code '+str(res.returncode))

	def update_local_password(self, username: str, password_hash: str) -> None:
		cmd = ['usermod', '-p', password_hash, username]
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, env=self.prepare_environment())
		if res.returncode != 0:
			raise Exception('usermod returned non-zero exit code '+str(res.returncode))

	def set_password_and_expiry(self, new_password: str, new_expiration_date: datetime) -> None:
		# check if dn of target computer object is known
		if self.tmp_dn.strip() == '': return
		if self.connection == None: raise Exception('No connection established')

		# apply Native LAPS JSON format
		if(self.cfg_use_native_laps_attribute_schema):
			print('Using Native LAPS JSON format')
			new_password = json.dumps({
				'p': new_password,
				'n': self.cfg_username,
				't': ('%0.2X' % dt_to_filetime(datetime.now().astimezone(timezone.utc))).lower()
			})

		# encrypt Native LAPS content
		ldap_password: str | bytes = new_password
		if(self.cfg_use_native_laps_attribute_schema and self.cfg_security_descriptor):
			print('Encrypting password to SID', self.cfg_security_descriptor)
			ldap_password = self.encrypt_password(new_password)

		# start query
		self.connection.modify(self.tmp_dn, {
			self.cfg_ldap_attribute_password_expiry: [(ldap3.MODIFY_REPLACE, [str( dt_to_filetime(new_expiration_date) )])],
			self.cfg_ldap_attribute_password: [(ldap3.MODIFY_REPLACE, [ldap_password])],
		})
		if self.connection.result['result'] == 0:
			print('Password and expiration date changed successfully in LDAP directory (attribute '+self.cfg_ldap_attribute_password+', new expiration '+str(new_expiration_date)+')')
		else:
			raise Exception('Could not update password in LDAP directory: '+str(self.connection.result))

		# update history
		if(self.tmp_password and self.cfg_history_size and self.cfg_history_size > 0
		and self.cfg_ldap_attribute_password_history and self.cfg_ldap_attribute_password_history.strip() != ''):
			self.connection.modify(self.tmp_dn, {
				self.cfg_ldap_attribute_password_history: [(ldap3.MODIFY_ADD, self.tmp_password)],
			})
			if self.connection.result['result'] != 0:
				raise Exception('Could not add previous password to history in LDAP directory: '+str(self.connection.result))

			# remove obsolete history entries
			self.connection.search(
				search_base = self.tmp_dn,
				search_filter = '(objectClass=*)',
				attributes = [self.cfg_ldap_attribute_password_history]
			)
			counter = 0
			delete_entries = []
			for entry in self.connection.entries:
				for value in entry[self.cfg_ldap_attribute_password_history]:
					counter += 1
					if counter > self.cfg_history_size:
						delete_entries.append(value)
				if len(delete_entries) > 0: # when giving ldap3 an empty array, all entries will be removed!
					self.connection.modify(self.tmp_dn, {
						self.cfg_ldap_attribute_password_history: [(ldap3.MODIFY_DELETE, delete_entries)],
					})
					if self.connection.result['result'] != 0:
						raise Exception('Could not remove old password from history in LDAP directory: '+str(self.connection.result))
				break

	def set_expiry(self, new_expiration_date: datetime) -> None:
		if self.connection == None: raise Exception('No connection established')
		self.connection.modify(self.tmp_dn, {
			self.cfg_ldap_attribute_password_expiry: [(ldap3.MODIFY_REPLACE, [str( dt_to_filetime(new_expiration_date) )])],
		})

	def encrypt_password(self, content: str) -> bytes:
		import dpapi_ng
		if self.server == None: raise Exception('No connection established')
		encrypted: bytes | None = None
		for server in self.server.servers:
			try: # one server could be unavailable, simply try the next one
				encrypted = dpapi_ng.ncrypt_protect_secret(
					content.encode('utf-16-le')+b"\x00\x00",
					self.cfg_security_descriptor,
					server = server.host,
				)
				break
			except Exception as e:
				print('Encryption attempt failed', e)
		if not encrypted: raise Exception('Unable to encrypt blob')

		# 0-4 - timestamp upper
		# 4-8 - timestamp lower
		# 8-12 - blob size, uint32
		# 12-16 - flags, currently always 0
		pre_magic = (
			self.rotate_and_pack_msdatetime(dt_to_filetime(datetime.now().astimezone(timezone.utc)))
			+ struct.pack('<i', len(encrypted))
			+ b'\x00\x00\x00\x00'
		)

		return pre_magic + encrypted

	def rotate_and_pack_msdatetime(self, dt: int) -> bytes:
		# MS AD uses upper time and lower time. The current ordering is backwards, which this fixes
		# this can be seen by using dnSpy to trace attempts to get-lapsadpassword, which fail on validating the datetime.
		left,right = struct.unpack('<LL',struct.pack('Q',dt))
		packed = struct.pack('<LL',right,left)
		return packed

	def generate_password(self) -> str:
		if isinstance(self.cfg_alphabet, str):
			return ''.join(secrets.choice(self.cfg_alphabet) for i in range(self.cfg_length))
		else:
			password = ''
			full_alphabet = ''
			for alphabet in self.cfg_alphabet:
				password += secrets.choice(alphabet)
				full_alphabet += alphabet
			for i in range(self.cfg_length - len(self.cfg_alphabet)):
				password += secrets.choice(full_alphabet)
			password_list = list(password)
			# shuffle all characters
			secrets.SystemRandom().shuffle(password_list)
			password = ''.join(password_list)
			return password

	def create_ldap_base(self, conn: ldap3.Connection) -> str:
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

	def get_connection_string(self) -> str:
		if self.connection == None: raise Exception('No connection established')
		return str(self.connection.server.host)+' '+str(self.connection.user)

	def load_settings(self) -> None:
		if(not path.isfile(self.cfg_path)):
			raise Exception('Config file not found: '+self.cfg_path)
		with open(self.cfg_path) as f:
			cfg_json = json.load(f)
			self.cfg_use_start_tls = cfg_json.get('use-starttls', self.cfg_use_start_tls)
			for server in cfg_json.get('server', ''):
				self.cfg_server.append({
					'address': str(server['address']),
					'port': int(server['port']),
					'ssl': bool(server['ssl'])
				})
			self.cfg_ca_certs_file = cfg_json.get('ca-certs-file', self.cfg_ca_certs_file)
			self.cfg_tls_validate = cfg_json.get('tls-validate', self.cfg_tls_validate)
			self.cfg_domain = cfg_json.get('domain', self.cfg_domain)
			self.cfg_ldap_query = cfg_json.get('ldap-query', self.cfg_ldap_query)
			self.cfg_cred_cache_file = cfg_json.get('cred-cache-file', self.cfg_cred_cache_file)
			self.cfg_client_keytab_file = cfg_json.get('client-keytab-file', self.cfg_client_keytab_file)
			self.cfg_username = cfg_json.get('password-change-user', self.cfg_username)
			self.cfg_days_valid = int(cfg_json.get('password-days-valid', self.cfg_days_valid))
			self.cfg_length = int(cfg_json.get('password-length', self.cfg_length))
			self.cfg_alphabet = cfg_json.get('password-alphabet', self.cfg_alphabet)
			self.cfg_use_native_laps_attribute_schema = bool(cfg_json.get('native-laps', self.cfg_use_native_laps_attribute_schema))
			self.cfg_security_descriptor = cfg_json.get('security-descriptor', self.cfg_security_descriptor)
			self.cfg_history_size = cfg_json.get('history-size', self.cfg_history_size)
			self.cfg_ldap_attribute_password = str(cfg_json.get('ldap-attribute-password', self.cfg_ldap_attribute_password))
			self.cfg_ldap_attribute_password_history = str(cfg_json.get('ldap-attribute-password-history', self.cfg_ldap_attribute_password_history))
			self.cfg_ldap_attribute_password_expiry = str(cfg_json.get('ldap-attribute-password-expiry', self.cfg_ldap_attribute_password_expiry))
			self.cfg_hostname = cfg_json.get('hostname', self.cfg_hostname)
			self.cfg_pam_services = cfg_json.get('pam-services', self.cfg_pam_services)
			self.cfg_pam_grace_period = int(cfg_json.get('pam-grace-period', self.cfg_pam_grace_period))
			self.cfg_hooks = cfg_json.get('hooks', self.cfg_hooks)


def get_current_password_hash(user_name: str, shadow_file: str = '/etc/shadow') -> str:
	with open(shadow_file, 'r') as file:
		for line in file:
			if line.startswith(f'{user_name}:'):
				parts = line.strip().split(':')
				if len(parts) > 1:
					root_hash = parts[1]
					return root_hash
				else:
					raise ValueError('Malformed entry for root user.')
	raise ValueError(f'User {user_name} not found in shadow file.')


def main() -> None:
	runner = LapsRunner()

	# parse arguments
	parser = argparse.ArgumentParser(epilog=__copyright__+' '+__author__+' - https://georg-sieber.de')
	parser.add_argument('-f', '--force', action='store_true', help='Force updating password, even if it is not expired')
	parser.add_argument('-p', '--pam', action='store_true', help='PAM mode - update password if configured user has logged out, even if it is not expired')
	parser.add_argument('-c', '--config', default=runner.cfg_path, help='Path to config file ['+str(runner.cfg_path)+']')
	args = parser.parse_args()
	if args.config: runner.cfg_path = args.config

	# start workflow
	try:
		with PidFile(__title__+'-runner') as p:
			runner.load_settings()
			runner.init_kerberos()
			runner.connect_to_server()
			runner.search_computer()

			if runner.tmp_expiry_date < datetime.now().astimezone(timezone.utc):
				print('Updating password (expired '+str(runner.tmp_expiry_date)+')')
				runner.update_password()

			elif args.force:
				print('Updating password (forced update)...')
				runner.update_password()

			elif args.pam:
				if 'PAM_SERVICE' not in os.environ or 'PAM_USER' not in os.environ:
					raise Exception('PAM_SERVICE or PAM_USER missing!')
				if runner.cfg_pam_services and os.environ['PAM_SERVICE'] not in runner.cfg_pam_services:
					runner.logger.debug(__title__+': PAM_SERVICE "'+os.environ['PAM_SERVICE']+'" is not one of '+str(runner.cfg_pam_services)+', exiting.')
					sys.exit(0)
				if os.environ['PAM_USER'] != runner.cfg_username:
					runner.logger.debug(__title__+': PAM_USER does not match the configured user, exiting.')
					sys.exit(0)
				if runner.cfg_pam_grace_period:
					runner.logger.debug(__title__+': PAM grace period - waiting '+str(runner.cfg_pam_grace_period)+' seconds...')
					# set expiration in directory, e.g. to handle reboots
					runner.set_expiry(datetime.now().astimezone(timezone.utc) + timedelta(seconds=runner.cfg_pam_grace_period))
					# wait grace period
					time.sleep(runner.cfg_pam_grace_period)
				print('Updating password (forced update by PAM)...')
				runner.update_password()

			else:
				print('Password will expire in '+str(runner.tmp_expiry_date)+', no need to update.')

	except (PidFileAlreadyLockedError, PidFileAlreadyRunningError) as e:
		print(e)
		print('Already running, exiting.')
		runner.logger.critical(__title__+': already running ('+str(e)+')')
		sys.exit(2)

	except Exception as e:
		print(traceback.format_exc())
		runner.logger.critical(__title__+': Error while executing workflow: '+str(e))
		sys.exit(1)

	return

if __name__ == '__main__':
	main()
