#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .__init__ import __title__, __version__, __website__, __author__, __copyright__
from .filetime import dt_to_filetime, filetime_to_dt

from pathlib import Path
from os import path
from crypt import crypt
from datetime import datetime, timedelta
from dns import resolver, rdatatype
from shutil import which
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
	server     = None
	connection = None
	logger     = None

	cfgPath             = '/etc/laps-runner.json'

	cfgCredCacheFile    = '/tmp/laps.temp'
	cfgClientKeytabFile = '/etc/krb5.keytab'
	cfgUseStartTls      = True
	cfgServer           = []
	cfgDomain           = ''

	cfgHostname         = None
	cfgUsername         = 'root' # the user, whose password should be changed
	cfgDaysValid        = 30 # how long the new password should be valid
	cfgLength           = 15 # the generated password length
	cfgAlphabet         = string.ascii_letters+string.digits+string.punctuation # allowed chars for the new password

	cfgUseNativeLapsAttributeSchema = True
	cfgSecurityDescriptor           = None
	cfgHistorySize                  = 0 # disabled by default because encryption is disabled by default
	cfgLdapAttributePassword        = 'msLAPS-Password'
	cfgLdapAttributePasswordHistory = 'msLAPS-EncryptedPasswordHistory'
	cfgLdapAttributePasswordExpiry  = 'msLAPS-PasswordExpirationTime'

	tmpDn         = ''
	tmpPassword   = None
	tmpExpiry     = ''
	tmpExpiryDate = ''

	def __init__(self, *args, **kwargs):
		# init logger
		self.logger = logging.getLogger('LAPS4LINUX')
		self.logger.setLevel(logging.DEBUG)
		self.logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))

		# show note
		print(__title__ + ' Runner' +' v'+__version__)
		print('If you like LAPS4LINUX please do not forget to give the repository a star ('+__website__+').')
		print('')

	def getHostname(self):
		if(self.cfgHostname == None or self.cfgHostname.strip() == ''):
			return socket.gethostname().split('.', 1)[0].upper()
		else:
			return self.cfgHostname.strip().upper()

	def initKerberos(self):
		# query new kerberos ticket
		cmd = ['kinit', '-k', '-c', self.cfgCredCacheFile, self.getHostname()+'$']
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
		if res.returncode != 0: raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def connectToServer(self):
		# set environment variables for kerberos operations
		os.environ['KRB5CCNAME'] = self.cfgCredCacheFile
		os.environ['KRB5_CLIENT_KTNAME'] = self.cfgClientKeytabFile

		# set TLS options
		tlssettings = ldap3.Tls(
			validate=ssl.CERT_REQUIRED
		)

		# connect to server with kerberos ticket
		serverArray = []
		if(len(self.cfgServer) == 0):
			# query domain controllers by dns lookup
			searchDomain = '.'+self.cfgDomain if self.cfgDomain!='' else ''
			res = resolver.resolve(qname=f'_ldap._tcp'+searchDomain, rdtype=rdatatype.SRV, lifetime=10, search=True)

			for srv in res.rrset:
				if(self.cfgUseStartTls):
					# strip the trailing . from the dns resolver for certificate verification reasons.
					serverArray.append(ldap3.Server(host=str(srv.target).rstrip('.'), port=389, tls=tlssettings, get_info=ldap3.ALL))
				else:
					serverArray.append(ldap3.Server(host=str(srv.target).rstrip('.'), port=636, use_ssl=True, tls=tlssettings, get_info=ldap3.ALL))
		else:
			# use servers given in config file
			for server in self.cfgServer:
				serverArray.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], get_info=ldap3.ALL))
		self.server = ldap3.ServerPool(serverArray, ldap3.ROUND_ROBIN, active=2, exhaust=True)
		if(self.cfgUseStartTls):
			self.connection = ldap3.Connection(self.server, version=3, authentication=ldap3.SASL, sasl_mechanism=ldap3.GSSAPI, auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND)
			self.connection.start_tls()
		else:
			self.connection = ldap3.Connection(self.server, version=3, authentication=ldap3.SASL, sasl_mechanism=ldap3.GSSAPI, auto_bind=True)
		print('Connected as: '+self.GetConnectionString())

	def searchComputer(self):
		if self.connection == None: raise Exception('No connection established')

		# check and escape input
		computerName = ldap3.utils.conv.escape_filter_chars(self.getHostname())

		# start query
		self.connection.search(
			search_base = self.createLdapBase(self.connection),
			search_filter = '(&(objectCategory=computer)(name='+computerName+'))',
			attributes = ldap3.ALL_ATTRIBUTES
		)
		for entry in self.connection.entries:
			# display result
			self.tmpDn = str(entry['distinguishedName'])
			try:
				self.tmpPassword = entry[self.cfgLdapAttributePassword][0]
			except Exception:
				pass
			try:
				self.tmpExpiry = str(entry[self.cfgLdapAttributePasswordExpiry])
			except Exception:
				pass
			try:
				# date conversion will fail if there is no previous expiration time saved
				self.tmpExpiryDate = filetime_to_dt( int(str(entry[self.cfgLdapAttributePasswordExpiry])) )
			except Exception as e:
				print('Unable to parse date '+str(self.tmpExpiry)+' - assuming that no expiration date is set.')
				self.tmpExpiryDate = datetime.utcfromtimestamp(0)
			return True

		# no result found
		raise Exception('No Result For: '+computerName)

	def updatePassword(self):
		# check if usermod is in PATH
		if(which('usermod') is None): raise Exception('usermod is not in PATH')

		# generate new values
		newPassword = self.generatePassword()
		newPasswordHashed = crypt(newPassword)
		newExpirationDate = datetime.now() + timedelta(days=self.cfgDaysValid)

		# update in directory
		self.setPasswordAndExpiry(newPassword, newExpirationDate)

		# update password in local database
		cmd = ['usermod', '-p', newPasswordHashed, self.cfgUsername]
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
		if res.returncode == 0:
			print('Password successfully changed in local database')
			self.logger.debug(__title__+': Changed password of user '+self.cfgUsername+' in local database')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def setPasswordAndExpiry(self, newPassword, newExpirationDate):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# apply Native LAPS JSON format
		if(self.cfgUseNativeLapsAttributeSchema):
			print('Using Native LAPS JSON format')
			newPassword = json.dumps({
				'p': newPassword,
				'n': self.cfgUsername,
				't': ('%0.2X' % dt_to_filetime(datetime.now())).lower()
			})

		# encrypt Native LAPS content
		if(self.cfgUseNativeLapsAttributeSchema and self.cfgSecurityDescriptor):
			print('Encrypting password to SID', self.cfgSecurityDescriptor)
			newPassword = self.encryptPassword(newPassword)

		# start query
		self.connection.modify(self.tmpDn, {
			self.cfgLdapAttributePasswordExpiry: [(ldap3.MODIFY_REPLACE, [str( dt_to_filetime(newExpirationDate) )])],
			self.cfgLdapAttributePassword: [(ldap3.MODIFY_REPLACE, [newPassword])],
		})
		if self.connection.result['result'] == 0:
			print('Password and expiration date changed successfully in LDAP directory (attribute '+self.cfgLdapAttributePassword+', new expiration '+str(newExpirationDate)+')')
		else:
			raise Exception('Could not update password in LDAP directory: '+str(self.connection.result))

		# update history
		if(self.tmpPassword and self.cfgHistorySize and self.cfgHistorySize > 0
		and self.cfgLdapAttributePasswordHistory and self.cfgLdapAttributePasswordHistory.strip() != ''):
			self.connection.modify(self.tmpDn, {
				self.cfgLdapAttributePasswordHistory: [(ldap3.MODIFY_ADD, self.tmpPassword)],
			})
			if self.connection.result['result'] != 0:
				raise Exception('Could not add previous password to history in LDAP directory: '+str(self.connection.result))

			# remove obsolete history entries
			self.connection.search(
				search_base=self.tmpDn,
				search_filter='(objectCategory=computer)',
				attributes=[self.cfgLdapAttributePasswordHistory]
			)
			counter = 0
			deleteEntries = []
			for entry in self.connection.entries:
				for value in entry[self.cfgLdapAttributePasswordHistory]:
					counter += 1
					if counter > self.cfgHistorySize:
						deleteEntries.append(value)
				if len(deleteEntries) > 0: # when giving ldap3 an empty array, all entries will be removed!
					self.connection.modify(self.tmpDn, {
						self.cfgLdapAttributePasswordHistory: [(ldap3.MODIFY_DELETE, deleteEntries)],
					})
					if self.connection.result['result'] != 0:
						raise Exception('Could not remove old password from history in LDAP directory: '+str(self.connection.result))
				break

	def encryptPassword(self, content):
		import dpapi_ng
		encrypted = None
		for server in self.server.servers:
			try: # one server could be unavailable, simply try the next one
				encrypted = dpapi_ng.ncrypt_protect_secret(
					content.encode('utf-16-le')+b"\x00\x00",
					self.cfgSecurityDescriptor,
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
		preMagic = (
			struct.pack('<Q', dt_to_filetime(datetime.now()))
			+ struct.pack('<i', len(encrypted))
			+ b'\x00\x00\x00\x00'
		)

		return preMagic + encrypted

	def generatePassword(self):
		return ''.join(secrets.choice(self.cfgAlphabet) for i in range(self.cfgLength))

	def createLdapBase(self, conn):
		if conn.server.info:
			return conn.server.info.raw['defaultNamingContext'][0].decode('utf-8')
		elif self.cfgDomain != '':
			# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
			search_base = ''
			base = self.cfgDomain.split('.')
			for b in base:
				search_base += 'DC=' + b + ','
			return search_base[:-1]
		else:
			raise Exception('Could not create LDAP search base: reading defaultNamingContext from LDAP directory failed and no domain given.')

	def GetConnectionString(self):
		return str(self.connection.server.host)+' '+str(self.connection.user)

	def LoadSettings(self):
		if(not path.isfile(self.cfgPath)):
			raise Exception('Config file not found: '+self.cfgPath)
		with open(self.cfgPath) as f:
			cfgJson = json.load(f)
			self.cfgUseStartTls = cfgJson.get('use-starttls', self.cfgUseStartTls)
			for server in cfgJson.get('server', ''):
				self.cfgServer.append({
					'address': str(server['address']),
					'port': int(server['port']),
					'ssl': bool(server['ssl'])
				})
			self.cfgDomain = cfgJson.get('domain', self.cfgDomain)
			self.cfgCredCacheFile = cfgJson.get('cred-cache-file', self.cfgCredCacheFile)
			self.cfgClientKeytabFile = cfgJson.get('client-keytab-file', self.cfgClientKeytabFile)
			self.cfgUsername = cfgJson.get('password-change-user', self.cfgUsername)
			self.cfgDaysValid = int(cfgJson.get('password-days-valid', self.cfgDaysValid))
			self.cfgLength = int(cfgJson.get('password-length', self.cfgLength))
			self.cfgAlphabet = str(cfgJson.get('password-alphabet', self.cfgAlphabet))
			self.cfgUseNativeLapsAttributeSchema = bool(cfgJson.get('native-laps', self.cfgUseNativeLapsAttributeSchema))
			self.cfgSecurityDescriptor = cfgJson.get('security-descriptor', self.cfgSecurityDescriptor)
			self.cfgHistorySize = cfgJson.get('history-size', self.cfgHistorySize)
			self.cfgLdapAttributePassword = str(cfgJson.get('ldap-attribute-password', self.cfgLdapAttributePassword))
			self.cfgLdapAttributePasswordHistory = str(cfgJson.get('ldap-attribute-password-history', self.cfgLdapAttributePasswordHistory))
			self.cfgLdapAttributePasswordExpiry = str(cfgJson.get('ldap-attribute-password-expiry', self.cfgLdapAttributePasswordExpiry))
			self.cfgHostname = cfgJson.get('hostname', self.cfgHostname)

def main():
	runner = LapsRunner()

	# parse arguments
	parser = argparse.ArgumentParser(epilog=__copyright__+' '+__author__+' - https://georg-sieber.de')
	parser.add_argument('-f', '--force', action='store_true', help='Force updating password, even if it is not expired')
	parser.add_argument('-c', '--config', default=runner.cfgPath, help='Path to config file ['+str(runner.cfgPath)+']')
	args = parser.parse_args()
	if args.config: runner.cfgPath = args.config

	# start workflow
	try:
		runner.LoadSettings()
		runner.initKerberos()
		runner.connectToServer()
		runner.searchComputer()

		if runner.tmpExpiryDate < datetime.now():
			print('Updating password (expired '+str(runner.tmpExpiryDate)+')')
			runner.updatePassword()
		elif args.force:
			print('Updating password (forced update)...')
			runner.updatePassword()
		else:
			print('Password will expire in '+str(runner.tmpExpiryDate)+', no need to update.')

	except Exception as e:
		print(traceback.format_exc())
		runner.logger.critical(__title__+': Error while executing workflow: '+str(e))
		exit(1)

	return

if __name__ == '__main__':
	main()

