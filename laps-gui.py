#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE, utils, MODIFY_REPLACE
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from pathlib import Path
from os import path
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


class LapsMainWindow(QMainWindow):
	PRODUCT_NAME      = "LAPS4LINUX"
	PRODUCT_VERSION   = "0.1.0"
	PRODUCT_WEBSITE   = "https://georg-sieber.de"

	cfgPath     = str(Path.home())+'/.laps-gui.json'
	cfgServer   = ""
	cfgDomain   = ""
	cfgUsername = ""
	cfgPassword = ""
	tmpDn       = ""

	def __init__(self):
		super(LapsMainWindow, self).__init__()
		self.LoadSettings()
		self.InitUI()

	def InitUI(self):
		# Menubar
		mainMenu = self.menuBar()

		# File Menu
		fileMenu = mainMenu.addMenu('&File')

		fileMenu.addSeparator()
		quitAction = QAction('&Quit', self)
		quitAction.setShortcut('Ctrl+Q')
		quitAction.triggered.connect(self.OnQuit)
		fileMenu.addAction(quitAction)

		# Help Menu
		editMenu = mainMenu.addMenu('&Help')

		aboutAction = QAction('&About', self)
		aboutAction.setShortcut('F1')
		#aboutAction.triggered.connect(self.OnOpenAboutDialog)
		editMenu.addAction(aboutAction)

		# Statusbar
		self.statusBar = self.statusBar()

		# Window Content
		grid = QGridLayout()

		self.lblSearchComputer = QLabel('Computer Name')
		grid.addWidget(self.lblSearchComputer, 0, 0)
		self.txtSearchComputer = QLineEdit()
		self.txtSearchComputer.returnPressed.connect(self.OnReturnSearch)
		grid.addWidget(self.txtSearchComputer, 1, 0)
		self.btnSearchComputer = QPushButton('Search')
		self.btnSearchComputer.clicked.connect(self.OnClickSearch)
		grid.addWidget(self.btnSearchComputer, 1, 1)

		self.lblPassword = QLabel('Password')
		grid.addWidget(self.lblPassword, 2, 0)
		self.txtPassword = QLineEdit()
		self.txtPassword.setReadOnly(True)
		font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
		font.setPointSize(14)
		self.txtPassword.setFont(font)
		grid.addWidget(self.txtPassword, 3, 0)

		self.lblPasswordExpires = QLabel('Password Expires')
		grid.addWidget(self.lblPasswordExpires, 4, 0)
		self.txtPasswordExpires = QLineEdit()
		self.txtPasswordExpires.setReadOnly(True)
		grid.addWidget(self.txtPasswordExpires, 5, 0)

		self.lblNewExpirationTime = QLabel('New Expiration Time')
		grid.addWidget(self.lblNewExpirationTime, 6, 0)
		self.cwNewExpirationTime = QCalendarWidget()
		grid.addWidget(self.cwNewExpirationTime, 7, 0)
		self.btnSetExpirationTime = QPushButton('Set')
		self.btnSetExpirationTime.setEnabled(False)
		self.btnSetExpirationTime.clicked.connect(self.OnClickSetExpiry)
		grid.addWidget(self.btnSetExpirationTime, 7, 1)

		widget = QWidget(self)
		widget.setLayout(grid)
		self.setCentralWidget(widget)

		# Window Settings
		self.setMinimumSize(490, 350)
		self.setWindowTitle(self.PRODUCT_NAME+" v"+self.PRODUCT_VERSION)

		# Show Note
		if not 'slub' in self.cfgDomain:
			self.statusBar.showMessage("If you like LAPS4LINUX please consider making a donation to support further development ("+self.PRODUCT_WEBSITE+").")

	def OnQuit(self, e):
		sys.exit()

	def OnReturnSearch(self):
		self.OnClickSearch(None)

	def OnClickSearch(self, e):
		# check and escape input
		computerName = self.txtSearchComputer.text()
		if computerName.strip() == "": return
		computerName = utils.conv.escape_filter_chars(computerName)

		# ask for credentials
		if not self.checkCredentials(): return

		try:
			# connect to server and start query
			s = Server(self.cfgServer, get_info=ALL)
			c = Connection(s, user=self.cfgDomain+'\\'+self.cfgUsername, password=self.cfgPassword, authentication=NTLM, auto_bind=True)
			c.search(search_base=self.createLdapBase(self.cfgDomain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+computerName+'))',attributes=['ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime','SAMAccountname','distinguishedName'])
			for entry in c.entries:
				# display result
				print('expiration time: '+str(entry['ms-Mcs-AdmPwdExpirationTime']))
				self.txtPassword.setText(str(entry['ms-Mcs-AdmPwd']))
				self.txtPasswordExpires.setText(str(entry['ms-Mcs-AdmPwdExpirationTime']))
				self.statusBar.showMessage('Found: '+str(entry['distinguishedName'])+' ('+self.cfgServer+': '+self.cfgUsername+'@'+self.cfgDomain+')')
				self.tmpDn = str(entry['distinguishedName'])
				self.btnSetExpirationTime.setEnabled(True)
				try:
					self.txtPasswordExpires.setText( str(filetime_to_dt( int(str(entry['ms-Mcs-AdmPwdExpirationTime'])) )) )
				except Exception as e: print(str(e))
				return

			# no result found
			self.txtPassword.setText('')
			self.txtPasswordExpires.setText('')
			self.tmpDn = ''
			self.btnSetExpirationTime.setEnabled(False)
			self.statusBar.showMessage('No Result For: '+computerName+' ('+self.cfgServer+': '+self.cfgUsername+'@'+self.cfgDomain+')')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			self.cfgUsername = ''
			self.cfgPassword = ''
			self.tmpDn = ''
			self.btnSetExpirationTime.setEnabled(False)

	def OnClickSetExpiry(self, e):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# ask for credentials
		if not self.checkCredentials(): return

		try:
			# calc new time
			newExpirationDateTime = dt_to_filetime( datetime.combine(self.cwNewExpirationTime.selectedDate().toPyDate(), datetime.min.time()) )
			print('new expiration time: '+str(newExpirationDateTime))

			# connect to server and start query
			s = Server(self.cfgServer, get_info=ALL)
			c = Connection(s, user=self.cfgDomain+'\\'+self.cfgUsername, password=self.cfgPassword, authentication=NTLM, auto_bind=True)
			c.modify(self.tmpDn, { 'ms-Mcs-AdmPwdExpirationTime': [(MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if c.result['result'] == 0:
				self.statusBar.showMessage('Expiration Date changed successfully: '+self.tmpDn+' ('+self.cfgServer+': '+self.cfgUsername+'@'+self.cfgDomain+')')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))

	def checkCredentials(self):
		if self.cfgServer == "":
			item, ok = QInputDialog.getText(self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
			if ok and item: self.cfgServer = item
			else: return False
		if self.cfgDomain == "":
			item, ok = QInputDialog.getText(self, '♕ Domain', 'Please enter your Domain name (e.g. example.com).')
			if ok and item: self.cfgDomain = item
			else: return False
		if self.cfgUsername == "":
			item, ok = QInputDialog.getText(self, '👤 Username', 'Please enter the username which should be used to connect to your LDAP server.')
			if ok and item: self.cfgUsername = item
			else: return False
		if self.cfgPassword == "":
			item, ok = QInputDialog.getText(self, '🔑 Password', 'Please enter the password which should be used to connect to your LDAP server.', QLineEdit.Password)
			if ok and item: self.cfgPassword = item
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
	app = QApplication(sys.argv)
	window = LapsMainWindow()
	window.show()
	sys.exit(app.exec_())

if __name__ == '__main__':
	main()
