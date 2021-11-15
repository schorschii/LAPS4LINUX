#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from os import path
from datetime import datetime
from dns import resolver, rdatatype
import ldap3
import getpass
import argparse
import json
import sys

# Microsoft Timestamp Conversion
EPOCH_TIMESTAMP = 11644473600  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
def dt_to_filetime(dt): # dt.timestamp() returns UTC time as expected by the LDAP server
	return int((dt.timestamp() + EPOCH_TIMESTAMP) * HUNDREDS_OF_NANOSECONDS)
def filetime_to_dt(ft): # ft is in UTC, fromtimestamp() converts to local time
	return datetime.fromtimestamp(int((ft / HUNDREDS_OF_NANOSECONDS) - EPOCH_TIMESTAMP))


class LapsCli():
	PRODUCT_NAME      = 'LAPS4LINUX CLI'
	PRODUCT_VERSION   = '1.5.2'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/laps4linux'

	useKerberos = True
	gcModeOn    = False
	server      = None
	connection  = None
	tmpDn       = ''

	cfgPresetDirWindows = sys.path[0]
	cfgPresetDirUnix    = '/etc'
	cfgPresetFile       = 'laps-client.json'
	cfgPresetPath       = (cfgPresetDirWindows if sys.platform.lower()=='win32' else cfgPresetDirUnix)+'/'+cfgPresetFile 

	cfgPath     = str(Path.home())+'/.laps-client.json'
	cfgServer   = []
	cfgDomain   = ''
	cfgUsername = ''
	cfgPassword = ''
	cfgLdapAttributes              = {
		'Administrator Password': 'ms-MCS-AdmPwd',
		'Password Expiration Date': 'ms-MCS-AdmPwdExpirationTime'
	}
	cfgLdapAttributePasswordExpiry = 'ms-MCS-AdmPwdExpirationTime'


	def __init__(self, useKerberos):
		self.LoadSettings()
		self.useKerberos = useKerberos

		# Show Version Information
		print(self.PRODUCT_NAME+' v'+self.PRODUCT_VERSION)
		print(self.PRODUCT_WEBSITE)

		print('')

	def GetAttributesAsDict(self):
		finalDict = {}
		if(isinstance(self.cfgLdapAttributes, list)):
			for attribute in self.cfgLdapAttributes:
				finalDict[attribute] = attribute
		elif(isinstance(self.cfgLdapAttributes, dict)):
			for title, attribute in self.cfgLdapAttributes.items():
				finalDict[str(title)] = str(attribute)
		return finalDict

	def SearchComputer(self, computerName):
		# check and escape input
		if computerName.strip() == '': return
		if not computerName == '*': computerName = ldap3.utils.conv.escape_filter_chars(computerName)

		# ask for credentials
		if not self.checkCredentialsAndConnect(): return
		self.printResult('Connection', str(self.connection.server)+' '+self.cfgUsername+'@'+self.cfgDomain)

		try:
			# compile query attributes
			attributes = ['SAMAccountname', 'distinguishedName']
			for title, attribute in self.GetAttributesAsDict().items():
				attributes.append(str(attribute))
			# start LDAP search
			count = 0
			self.connection.search(
				search_base=self.createLdapBase(self.cfgDomain),
				search_filter='(&(objectCategory=computer)(name='+computerName+'))',
				attributes=attributes
			)
			for entry in self.connection.entries:
				count += 1
				# display result list
				if computerName == '*':
					displayValues = []
					for title, attribute in self.GetAttributesAsDict().items():
						displayValues.append(str(entry[str(attribute)]).ljust(25))
					print(str(entry['SAMAccountname'])+' : '+str.join(' : ', displayValues))
				# display single result
				else:
					self.printResult('Found', str(entry['distinguishedName']))
					self.tmpDn = str(entry['distinguishedName'])
					self.queryAttributes()
					return

			# no result found
			if count == 0: self.printResult('No Result For', computerName)
		except Exception as e:
			# display error
			self.printResult('Error', str(e))
			print(str(e))
			# reset connection
			self.server = None
			self.connection = None

		self.tmpDn = ''

	def SetExpiry(self, newExpirationDateTimeString):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		try:
			# calc new time
			newExpirationDate = datetime.strptime(newExpirationDateTimeString, '%Y-%m-%d %H:%M:%S')
			newExpirationDateTime = dt_to_filetime( newExpirationDate )
			self.printResult('New Expiration', str(newExpirationDateTime)+' ('+str(newExpirationDate)+')')

			# start LDAP modify
			self.connection.modify(self.tmpDn, { self.cfgLdapAttributePasswordExpiry: [(ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if self.connection.result['result'] == 0:
				print('Expiration Date Changed Successfully.')
			else:
				print('Unable to change expiration date. '+str(self.connection.result['message']))

		except Exception as e:
			# display error
			self.printResult('Error', str(e))
			# reset connection
			self.server = None
			self.connection = None

	def queryAttributes(self):
		if(not self.reconnectForAttributeQuery()):
			self.btnSetExpirationTime.setEnabled(False)
			self.btnSearchComputer.setEnabled(True)
			return

		# compile query attributes
		attributes = ['SAMAccountname', 'distinguishedName']
		for title, attribute in self.GetAttributesAsDict().items():
			attributes.append(str(attribute))
		# start LDAP search
		self.connection.search(
			search_base=self.tmpDn,
			search_filter='(objectCategory=computer)',
			attributes=attributes
		)
		for entry in self.connection.entries:
			# display single result
			for title, attribute in self.GetAttributesAsDict().items():
				if(str(attribute) == self.cfgLdapAttributePasswordExpiry):
					try:
						self.printResult(str(title), str(entry[str(attribute)])+' ('+str(filetime_to_dt( int(str(entry[str(attribute)])) ))+')')
					except Exception as e:
						self.printResult('Error', str(e))
						self.printResult(str(title), str(entry[str(attribute)]))
				else:
					self.printResult(str(title), str(entry[str(attribute)]))
			return

	def printResult(self, attribute, value):
		print((attribute+':').ljust(26)+value)

	def checkCredentialsAndConnect(self):
		# ask for server address and domain name if not already set via config file
		if self.cfgDomain == "":
			item = input('♕ Domain Name (e.g. example.com): ')
			if item and item.strip() != "":
				self.cfgDomain = item
				self.server = None
			else: return False
		if len(self.cfgServer) == 0:
			# query domain controllers by dns lookup
			try:
				res = resolver.query(qname=f"_ldap._tcp.{self.cfgDomain}", rdtype=rdatatype.SRV, lifetime=10)
				for srv in res.rrset:
					serverEntry = {
						'address': str(srv.target),
						'port': srv.port,
						'ssl': (srv.port == 636)
					}
					print('DNS auto discovery found server: '+json.dumps(serverEntry))
					self.cfgServer.append(serverEntry)
			except Exception as e: print('DNS auto discovery failed: '+str(e))
			# ask user to enter server names if auto discovery was not successful
			if len(self.cfgServer) == 0:
				item = input('💻 LDAP Server Address: ')
				if item and item.strip() != "":
					self.cfgServer.append({
						'address': item,
						'port': 389,
						'ssl': False
					})
					self.server = None
		self.SaveSettings()

		# establish server connection
		if self.server == None:
			try:
				serverArray = []
				for server in self.cfgServer:
					port = server['port']
					if('gc-port' in server):
						port = server['gc-port']
						self.gcModeOn = True
					serverArray.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], get_info=ldap3.ALL))
				self.server = ldap3.ServerPool(serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)
			except Exception as e:
				print('Error connecting to LDAP server: ', str(e))
				return False

		# try to bind to server via Kerberos
		try:
			if(self.useKerberos):
				self.connection = ldap3.Connection(
					self.server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.KERBEROS,
					auto_referrals=True,
					auto_bind=True
				)
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

		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(
				self.server,
				user=self.cfgUsername+'@'+self.cfgDomain,
				password=self.cfgPassword,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=True
			)
			#self.connection.bind()
		except Exception as e:
			self.cfgUsername = ''
			self.cfgPassword = ''
			print('Error binding to LDAP server: ', str(e))
			return False

		return True

	def reconnectForAttributeQuery(self):
		# global catalog was not used for search - we can use the same connection for attribute query
		if(not self.gcModeOn): return True
		# global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
		# -> that's why we need to establish a new connection to the "normal" LDAP port
		# LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
		serverArray = []
		for server in self.cfgServer:
			serverArray.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], get_info=ldap3.ALL))
		server = ldap3.ServerPool(serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)
		# try to bind to server via Kerberos
		try:
			if(self.useKerberos):
				self.connection = ldap3.Connection(server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.KERBEROS,
					auto_referrals=True,
					auto_bind=True
				)
				return True
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))
		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(server,
				user=self.cfgUsername+'@'+self.cfgDomain,
				password=self.cfgPassword,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=True
			)
			return True
		except Exception as e:
			print('Error binding to LDAP server: '+str(e))
			return False

	def createLdapBase(self, domain):
		# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
		search_base = ""
		base = domain.split(".")
		for b in base:
			search_base += "DC=" + b + ","
		return search_base[:-1]

	def LoadSettings(self):
		if(path.isfile(self.cfgPath)): cfgPath = self.cfgPath
		elif(path.isfile(self.cfgPresetPath)): cfgPath = self.cfgPresetPath
		else: return
		try:
			with open(cfgPath) as f:
				cfgJson = json.load(f)
				self.cfgServer = cfgJson.get('server', '')
				self.cfgDomain = cfgJson.get('domain', '')
				self.cfgUsername = cfgJson.get('username', '')
				self.cfgLdapAttributePasswordExpiry = str(cfgJson.get('ldap-attribute-password-expiry', self.cfgLdapAttributePasswordExpiry))
				tmpLdapAttributes = cfgJson.get('ldap-attributes', self.cfgLdapAttributes)
				if(isinstance(tmpLdapAttributes, list) or isinstance(tmpLdapAttributes, dict)):
					self.cfgLdapAttributes = tmpLdapAttributes
		except Exception as e:
			print('Error loading settings file: '+str(e))

	def SaveSettings(self):
		try:
			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'server': self.cfgServer,
					'domain': self.cfgDomain,
					'username': self.cfgUsername,
					'ldap-attribute-password-expiry': self.cfgLdapAttributePasswordExpiry,
					'ldap-attributes': self.cfgLdapAttributes
				}, json_file, indent=4)
		except Exception as e:
			print('Error saving settings file: '+str(e))

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('search', default=None, metavar='COMPUTERNAME', help='Search for this computer and display the admin password. Use "*" to display all computer passwords found in LDAP directory.')
	parser.add_argument('-e', '--set-expiry', default=None, metavar='"2020-01-01 00:00:00"', help='Set new expiration date for computer found by search string.')
	parser.add_argument('-K', '--no-kerberos', action='store_true', help='Do not use Kerberos authentication if available, ask for LDAP simple bind credentials.')
	args = parser.parse_args()

	cli = LapsCli(not args.no_kerberos)

	if args.search and args.search.strip() == '*':
		cli.SearchComputer('*')
		return

	if args.search and args.search.strip() != '':
		cli.SearchComputer(args.search)

		if args.set_expiry and args.set_expiry.strip() != '':
			cli.SetExpiry(args.set_expiry.strip())

		return

	print('Please tell me what to do. Use --help for more information.')
	return

if __name__ == '__main__':
	main()
