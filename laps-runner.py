#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from os import path
from crypt import crypt
from datetime import datetime, timedelta
from dns import resolver, rdatatype
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

# Microsoft Timestamp Conversion
EPOCH_TIMESTAMP = 11644473600  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
def dt_to_filetime(dt): # dt.timestamp() returns UTC time as expected by the LDAP server
	return int((dt.timestamp() + EPOCH_TIMESTAMP) * HUNDREDS_OF_NANOSECONDS)
def filetime_to_dt(ft): # ft is in UTC, fromtimestamp() converts to local time
	return datetime.fromtimestamp(int((ft / HUNDREDS_OF_NANOSECONDS) - EPOCH_TIMESTAMP))


class LapsRunner():
	PRODUCT_NAME      = 'LAPS4LINUX Runner'
	PRODUCT_VERSION   = '1.5.2'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/laps4linux'

	server     = None
	connection = None
	logger     = None

	cfgPath             = '/etc/laps-runner.json'

	cfgCredCacheFile    = '/tmp/laps.temp'
	cfgClientKeytabFile = '/etc/krb5.keytab'
	cfgServer           = []
	cfgDomain           = ''

	cfgHostname         = None
	cfgUsername         = 'root' # the user, whose password should be changed
	cfgDaysValid        = 30 # how long the new password should be valid
	cfgLength           = 15 # the generated password length
	cfgAlphabet         = string.ascii_letters+string.digits # allowed chars for the new password

	cfgLdapAttributePassword       = 'ms-MCS-AdmPwd'
	cfgLdapAttributePasswordExpiry = 'ms-MCS-AdmPwdExpirationTime'

	tmpDn         = ''
	tmpPassword   = ''
	tmpExpiry     = ''
	tmpExpiryDate = ''

	def __init__(self, *args, **kwargs):
		# init logger
		self.logger = logging.getLogger('LAPS4LINUX')
		self.logger.setLevel(logging.DEBUG)
		self.logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))

		# show note
		print(self.PRODUCT_NAME+' v'+self.PRODUCT_VERSION)
		if not 'slub' in self.cfgDomain:
			print('If you like LAPS4LINUX please consider making a donation to support further development ('+self.PRODUCT_WEBSITE+').')
		else:
			print(self.PRODUCT_WEBSITE)
		print('')

	def getHostname(self):
		if(self.cfgHostname == None or self.cfgHostname.strip() == ''):
			return socket.gethostname().upper()
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

		# connect to server with kerberos ticket
		serverArray = []
		if(len(self.cfgServer) == 0):
			# query domain controllers by dns lookup
			res = resolver.query(qname=f"_ldap._tcp.{self.cfgDomain}", rdtype=rdatatype.SRV, lifetime=10)
			for srv in res.rrset:
				serverArray.append(ldap3.Server(host=str(srv.target), port=636, use_ssl=True, get_info=ldap3.ALL))
		else:
			# use servers given in config file
			for server in self.cfgServer:
				serverArray.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], get_info=ldap3.ALL))
		self.server = ldap3.ServerPool(serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)
		self.connection = ldap3.Connection(self.server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, auto_bind=True)
		print('Connected as: '+str(self.connection.server)+' '+self.connection.extend.standard.who_am_i()+'@'+self.cfgDomain)

	def searchComputer(self):
		if self.connection == None: raise Exception('No connection established')

		# check and escape input
		computerName = ldap3.utils.conv.escape_filter_chars(self.getHostname())

		# start query
		self.connection.search(
			search_base = self.createLdapBase(self.cfgDomain),
			search_filter = '(&(objectCategory=computer)(name='+computerName+'))',
			attributes = [ self.cfgLdapAttributePassword, self.cfgLdapAttributePasswordExpiry, 'SAMAccountname', 'distinguishedName' ]
		)
		for entry in self.connection.entries:
			# display result
			self.tmpDn = str(entry['distinguishedName'])
			self.tmpPassword = str(entry[self.cfgLdapAttributePassword])
			self.tmpExpiry = str(entry[self.cfgLdapAttributePasswordExpiry])
			try:
				# date conversion will fail if there is no previous expiration time saved
				self.tmpExpiryDate = filetime_to_dt( int(str(entry[self.cfgLdapAttributePasswordExpiry])) )
			except Exception as e:
				print('Unable to parse date '+str(entry[self.cfgLdapAttributePasswordExpiry])+' - assuming that no expiration date is set.')
				self.tmpExpiryDate = datetime.utcfromtimestamp(0)
			return True

			# no result found
			raise Exception('No Result For: '+computerName)

		self.tmpDn = ''
		self.tmpPassword = ''
		self.tmpExpiry = ''
		self.tmpExpiryDate = ''
		return False

	def updatePassword(self):
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
			print('Password successfully changed in local database.')
			self.logger.debug(self.PRODUCT_NAME+': Changed password of user '+self.cfgUsername+' in local database.')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def setPasswordAndExpiry(self, newPassword, newExpirationDate):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# calc new time
		newExpirationDateTime = dt_to_filetime( newExpirationDate )

		# start query
		self.connection.modify(self.tmpDn, {
			self.cfgLdapAttributePasswordExpiry: [(ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])],
			self.cfgLdapAttributePassword: [(ldap3.MODIFY_REPLACE, [str(newPassword)])],
		})
		if self.connection.result['result'] == 0:
			print('Password and expiration date changed successfully in LDAP directory (new expiration '+str(newExpirationDate)+').')
		else:
			raise Exception('Could not update password in LDAP directory.')

	def generatePassword(self):
		return ''.join(secrets.choice(self.cfgAlphabet) for i in range(self.cfgLength))

	def createLdapBase(self, domain):
		search_base = ""
		base = domain.split(".")
		for b in base:
			search_base += "DC=" + b + ","
		return search_base[:-1]

	def LoadSettings(self):
		if(not path.isfile(self.cfgPath)):
			raise Exception('Config file not found: '+self.cfgPath)
		with open(self.cfgPath) as f:
			cfgJson = json.load(f)
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
			self.cfgLdapAttributePassword = str(cfgJson.get('ldap-attribute-password', self.cfgLdapAttributePassword))
			self.cfgLdapAttributePasswordExpiry = str(cfgJson.get('ldap-attribute-password-expiry', self.cfgLdapAttributePasswordExpiry))
			self.cfgHostname = cfgJson.get('hostname', self.cfgHostname)

def main():
	runner = LapsRunner()

	# parse arguments
	parser = argparse.ArgumentParser()
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
		runner.logger.critical(runner.PRODUCT_NAME+': Error while executing workflow: '+str(e))
		exit(1)

	return

if __name__ == '__main__':
	main()
