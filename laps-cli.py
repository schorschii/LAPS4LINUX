#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE, utils, MODIFY_REPLACE, Tls, SASL, KERBEROS
from pathlib import Path
from os import path
from datetime import datetime
import getpass
import argparse
import json
import sys

# Microsoft Timestamp Conversion
from datetime import datetime, timedelta, tzinfo
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


class LapsCli():
	PRODUCT_NAME      = 'LAPS4LINUX CLI'
	PRODUCT_VERSION   = '1.0.0'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/laps4linux'

	server      = None
	connection  = None

	cfgPath     = str(Path.home())+'/.laps-client.json'
	cfgServer   = ''
	cfgPort     = 389 #636 for SSL
	cfgSsl      = False
	cfgDomain   = ''
	cfgUsername = ''
	cfgPassword = ''
	tmpDn       = ''

	def __init__(self, *args, **kwargs):
		self.LoadSettings()

		# Show Note
		print(self.PRODUCT_NAME+' v'+self.PRODUCT_VERSION)
		if not 'slub' in self.cfgDomain:
			print('If you like LAPS4LINUX please consider making a donation to support further development ('+self.PRODUCT_WEBSITE+').')
		else:
			print(self.PRODUCT_WEBSITE)

		print('')

	def SearchComputer(self, computerName):
		# check and escape input
		if computerName.strip() == '': return
		if not computerName == '*': computerName = utils.conv.escape_filter_chars(computerName)

		# ask for credentials
		if not self.checkCredentialsAndConnect(): return
		print('Connection: '+self.cfgServer+':'+str(self.cfgPort)+' '+self.cfgUsername+'@'+self.cfgDomain)

		try:
			# start LDAP query
			count = 0
			self.connection.search(search_base=self.createLdapBase(self.cfgDomain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+computerName+'))',attributes=['ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime','SAMAccountname','distinguishedName'])
			for entry in self.connection.entries:
				count += 1
				# display result
				if computerName == '*':
					print(str(entry['SAMAccountname'])+' : '+str(entry['ms-Mcs-AdmPwd']))
				else:
					print('Found:      '+str(entry['distinguishedName']))
					print('Password:   '+str(entry['ms-Mcs-AdmPwd']))
					self.tmpDn = str(entry['distinguishedName'])
					try:
						print( 'Expiration: '+str(entry['ms-Mcs-AdmPwdExpirationTime'])+' ('+str(filetime_to_dt( int(str(entry['ms-Mcs-AdmPwdExpirationTime'])) ))+')' )
					except Exception as e:
						print('Error: '+str(e))
						print('Expiration: '+str(entry['ms-Mcs-AdmPwdExpirationTime']))
					return

			# no result found
			if count == 0: print('No Result For: '+computerName)
		except Exception as e:
			# display error
			print('Error: '+str(e))

		self.tmpDn = ''

	def SetExpiry(self, newExpirationDateTimeString):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# ask for credentials
		if not self.checkCredentialsAndConnect(): return

		try:
			# calc new time
			newExpirationDate = datetime.strptime(newExpirationDateTimeString, '%Y-%m-%d %H:%M:%S')
			newExpirationDateTime = dt_to_filetime( newExpirationDate )
			print('New Expiration: '+str(newExpirationDateTime)+' ('+str(newExpirationDate)+')')

			# start LDAP query
			self.connection.modify(self.tmpDn, { 'ms-Mcs-AdmPwdExpirationTime': [(MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if self.connection.result['result'] == 0:
				print('Expiration Date Changed Successfully.')
		except Exception as e:
			# display error
			print('Error: '+str(e))

	def checkCredentialsAndConnect(self):
		if self.server != None and self.connection != None: return True

		# ask for server address and domain name if not already set via config file
		if self.cfgServer == "":
			item = input('💻 LDAP Server Address: ')
			if item and item.strip() != "":
				self.cfgServer = item
				self.server = None
			else: return False
		if self.cfgDomain == "":
			item = input('♕ Domain Name (e.g. example.com): ')
			if item and item.strip() != "":
				self.cfgDomain = item
				self.server = None
			else: return False
		self.SaveSettings()

		# establish server connection
		if self.server == None:
			try:
				self.server = Server(self.cfgServer, port=self.cfgPort, use_ssl=self.cfgSsl, get_info=ALL)
			except Exception as e:
				print('Error connecting to LDAP server: ', str(e))
				return False

		# try to bind to server via Kerberos
		try:
			self.connection = Connection(self.server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
			#self.connection.bind()
			return True # return if connection created successfully
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))

		# ask for username and password for NTLM bind
		if self.cfgUsername == "":
			item = input('👤 Username ['+getpass.getuser()+']: ') or getpass.getuser()
			if item and item.strip() != "":
				self.cfgUsername = item
				self.connection = None
			else: return False
		if self.cfgPassword == "":
			item = getpass.getpass('🔑 Password for »'+self.cfgUsername+'«: ')
			if item and item.strip() != "":
				self.cfgPassword = item
				self.connection = None
			else: return False
		self.SaveSettings()

		# try to bind to server via NTLM
		try:
			self.connection = Connection(self.server, user=self.cfgDomain+'\\'+self.cfgUsername, password=self.cfgPassword, authentication=NTLM, auto_bind=True)
			#self.connection.bind()
		except Exception as e:
			self.cfgUsername = ''
			self.cfgPassword = ''
			print('Error binding to LDAP server: ', str(e))
			return False

		return True

	def createLdapBase(self, domain):
		# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
		search_base = ""
		base = domain.split(".")
		for b in base:
			search_base += "DC=" + b + ","
		return search_base[:-1]

	def LoadSettings(self):
		if(not path.isfile(self.cfgPath)): return
		try:
			with open(self.cfgPath) as f:
				cfgJson = json.load(f)
				self.cfgServer = cfgJson.get('server', '')
				self.cfgDomain = cfgJson.get('domain', '')
				self.cfgUsername = cfgJson.get('username', '')
				self.cfgPort = int(cfgJson.get('port', self.cfgPort))
				self.cfgSsl = bool(cfgJson.get('ssl', self.cfgSsl))
		except Exception as e:
			print('Error loading settings file: '+str(e))

	def SaveSettings(self):
		try:
			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'server': self.cfgServer,
					'port': self.cfgPort,
					'ssl': self.cfgSsl,
					'domain': self.cfgDomain,
					'username': self.cfgUsername
				}, json_file, indent=4)
		except Exception as e:
			print('Error saving settings file: '+str(e))

def main():
	cli = LapsCli()

	parser = argparse.ArgumentParser()
	parser.add_argument('--show-all', action='store_true', help='Show passwords for all computer')
	parser.add_argument('--search', default=None, help='Search for this computer and display password')
	parser.add_argument('--set-expiry', default=None, help='Set new expiration date (format: "2020-01-01 00:00:00")')
	args = parser.parse_args()

	if args.show_all:
		cli.SearchComputer('*')
		return

	if args.search and args.search.strip() != "":
		cli.SearchComputer(args.search)

		if args.set_expiry and args.set_expiry.strip() != "":
			cli.SetExpiry(args.set_expiry.strip())

		return

	print('Please tell me what to do. Use --help for more information.')
	return

if __name__ == '__main__':
	main()
