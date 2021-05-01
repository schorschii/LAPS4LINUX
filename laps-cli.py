#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE, utils, MODIFY_REPLACE
from pathlib import Path
from os import path
from getpass import getpass
from datetime import datetime
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
	PRODUCT_NAME      = "LAPS4LINUX CLI"
	PRODUCT_VERSION   = "1.0.0"
	PRODUCT_WEBSITE   = "https://github.com/schorschii/laps4linux"

	cfgPath     = str(Path.home())+'/.laps-gui.json'
	cfgServer   = ""
	cfgDomain   = ""
	cfgUsername = ""
	cfgPassword = ""
	tmpDn       = ""

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
		if not self.checkCredentials(): return
		print('Connection: '+self.cfgServer+': '+self.cfgUsername+'@'+self.cfgDomain)

		try:
			# connect to server and start query
			count = 0
			s = Server(self.cfgServer, get_info=ALL)
			c = Connection(s, user=self.cfgDomain+'\\'+self.cfgUsername, password=self.cfgPassword, authentication=NTLM, auto_bind=True)
			c.search(search_base=self.createLdapBase(self.cfgDomain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+computerName+'))',attributes=['ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime','SAMAccountname','distinguishedName'])
			for entry in c.entries:
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
			self.cfgUsername = ''
			self.cfgPassword = ''

		self.tmpDn = ''

	def SetExpiry(self, newExpirationDateTimeString):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# ask for credentials
		if not self.checkCredentials(): return

		try:
			# calc new time
			newExpirationDate = datetime.strptime(newExpirationDateTimeString, '%Y-%m-%d %H:%M:%S')
			newExpirationDateTime = dt_to_filetime( newExpirationDate )
			print('New Expiration: '+str(newExpirationDateTime)+' ('+str(newExpirationDate)+')')

			# connect to server and start query
			s = Server(self.cfgServer, get_info=ALL)
			c = Connection(s, user=self.cfgDomain+'\\'+self.cfgUsername, password=self.cfgPassword, authentication=NTLM, auto_bind=True)
			c.modify(self.tmpDn, { 'ms-Mcs-AdmPwdExpirationTime': [(MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if c.result['result'] == 0:
				print('Expiration Date Changed Successfully.')
		except Exception as e:
			# display error
			print('Error: '+str(e))

	def checkCredentials(self):
		if self.cfgServer == "":
			item = input('💻 LDAP Server Address: ')
			if item and item.strip() != "": self.cfgServer = item
			else: return False
		if self.cfgDomain == "":
			item = input('♕ Domain Name (e.g. example.com): ')
			if item and item.strip() != "": self.cfgDomain = item
			else: return False
		if self.cfgUsername == "":
			item = input('👤 Username: ')
			if item and item.strip() != "": self.cfgUsername = item
			else: return False
		if self.cfgPassword == "":
			item = getpass('🔑 Password: ')
			if item and item.strip() != "": self.cfgPassword = item
			else: return False
		self.SaveSettings()
		return True

	def createLdapBase(self, domain):
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
				self.cfgServer = cfgJson['server']
				self.cfgDomain = cfgJson['domain']
				self.cfgUsername = cfgJson['username']
		except Exception as e:
			print(str(e))
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle('Error loading command file')
			msg.setText(str(e))
			msg.setStandardButtons(QMessageBox.Ok)
			retval = msg.exec_()

	def SaveSettings(self):
		try:
			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'server': self.cfgServer,
					'domain': self.cfgDomain,
					'username': self.cfgUsername
				}, json_file, indent=4)
		except Exception as e:
			print(str(e))
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle('Error loading command file')
			msg.setText(str(e))
			msg.setStandardButtons(QMessageBox.Ok)
			retval = msg.exec_()

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
