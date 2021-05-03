#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE, utils, MODIFY_REPLACE, SASL, KERBEROS
from pathlib import Path
from os import path
from crypt import crypt
import subprocess
import secrets
import string
import socket
import getpass
import argparse
import configparser
import sys, os
import logging
import logging.handlers

# Microsoft Timestamp Conversion
from datetime import datetime, timedelta, tzinfo, date
from calendar import timegm
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
ZERO = timedelta(0)
HOUR = timedelta(hours=1)
class UTC(tzinfo):
	def utcoffset(self, dt):
		return ZERO
	def tzname(self, dt):
		return "UTC"
	def dst(self, dt):
		return ZERO
def dt_to_filetime(dt):
	utc = UTC()
	if(dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None): dt = dt.replace(tzinfo=utc)
	return EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)
def filetime_to_dt(ft):
	return datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)


class LapsRunner():
	PRODUCT_NAME      = 'LAPS4LINUX Runner'
	PRODUCT_VERSION   = '1.0.0'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/laps4linux'

	server     = None
	connection = None
	logger     = None

	cfgCredCacheFile    = '/tmp/laps.temp'
	cfgClientKeytabFile = '/etc/krb5.keytab'
	cfgPath       = '/etc/laps-runner.ini'
	cfgServer     = ''
	cfgPort       = 389
	cfgSsl        = False
	cfgDomain     = ''

	cfgUsername   = 'root' # the user, whose password should be changed
	cfgDaysValid  = 30 # how long the new password should be valid
	cfgLength     = 15 # the generated password length
	cfgAlphabet   = string.ascii_letters+string.digits # allowed chars for the new password

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

	def initKerberos(self):
		# query new kerberos ticket
		#sudo kinit -k -c /tmp/laps.temp COMPUTERNAME$
		#sudo klist -c /tmp/laps.temp
		samaccountname = socket.gethostname().upper()+'$'
		cmd = ['kinit', '-k', '-c', self.cfgCredCacheFile, samaccountname]
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
		if res.returncode != 0: raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def connectToServer(self):
		# set environment variables for kerberos operations
		os.environ['KRB5CCNAME'] = self.cfgCredCacheFile
		os.environ['KRB5_CLIENT_KTNAME'] = self.cfgClientKeytabFile

		# connect to server with kerberos ticket
		self.server = Server(self.cfgServer, port=self.cfgPort, use_ssl=self.cfgSsl)
		self.connection = Connection(self.server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
		print('Connected as: '+self.cfgServer+':'+str(self.cfgPort)+' '+self.connection.extend.standard.who_am_i()+'@'+self.cfgDomain)

	def searchComputer(self):
		if self.connection == None: raise Exception('No connection established')

		# check and escape input
		computerName = utils.conv.escape_filter_chars(socket.gethostname().upper())

		# start query
		self.connection.search(search_base=self.createLdapBase(self.cfgDomain), search_filter='(&(objectCategory=computer)(name='+computerName+'))',attributes=['ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime','SAMAccountname','distinguishedName'])
		for entry in self.connection.entries:
			# display result
			self.tmpDn = str(entry['distinguishedName'])
			self.tmpPassword = str(entry['ms-Mcs-AdmPwd'])
			self.tmpExpiry = str(entry['ms-Mcs-AdmPwdExpirationTime'])
			try:
				# date conversion will fail if there is no previous expiration time saved
				self.tmpExpiryDate = filetime_to_dt( int(str(entry['ms-Mcs-AdmPwdExpirationTime'])) )
			except Exception as e:
				print('Unable to parse date '+str(entry['ms-Mcs-AdmPwdExpirationTime'])+' - assuming that no expiration date is set.')
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
			self.logger.debug('LAPS4LINUX: Changed password of user '+self.cfgUsername+' in local database.')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))

	def setPasswordAndExpiry(self, newPassword, newExpirationDate):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# calc new time
		newExpirationDateTime = dt_to_filetime( newExpirationDate )

		# start query
		self.connection.modify(self.tmpDn, {
			'ms-Mcs-AdmPwdExpirationTime': [(MODIFY_REPLACE, [str(newExpirationDateTime)])],
			'ms-Mcs-AdmPwd': [(MODIFY_REPLACE, [str(newPassword)])],
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
		configParser = configparser.ConfigParser({
			'server': self.cfgServer,
			'domain': self.cfgDomain,
			'port': self.cfgPort,
			'ssl': self.cfgSsl,
			'cred-cache-file': self.cfgCredCacheFile,
			'client-keytab-file': self.cfgClientKeytabFile,
			'password-change-user': self.cfgUsername,
			'password-days-valid': self.cfgDaysValid,
			'password-length': self.cfgLength,
			'password-alphabet': self.cfgAlphabet
		})
		configParser.read(self.cfgPath)
		self.cfgServer = configParser.get('runner', 'server')
		self.cfgDomain = configParser.get('runner', 'domain')
		self.cfgPort = int(configParser.get('runner', 'port'))
		self.cfgSsl = False if configParser.get('runner', 'ssl').strip() == '0' else True
		self.cfgCredCacheFile = configParser.get('runner', 'cred-cache-file')
		self.cfgClientKeytabFile = configParser.get('runner', 'client-keytab-file')
		self.cfgUsername = configParser.get('runner', 'password-change-user')
		self.cfgDaysValid = int(configParser.get('runner', 'password-days-valid'))
		self.cfgLength = int(configParser.get('runner', 'password-length'))
		self.cfgAlphabet = configParser.get('runner', 'password-alphabet')

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
		print('Error: '+str(e))
		runner.logger.critical('LAPS4LINUX: Error while executing workflow '+str(e))
		exit(1)

	return

if __name__ == '__main__':
	main()
