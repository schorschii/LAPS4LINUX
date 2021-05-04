#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE, utils, MODIFY_REPLACE, Tls, SASL, KERBEROS
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from pathlib import Path
from os import path
from datetime import datetime
import getpass
import json
import sys

# Microsoft Timestamp Conversion
EPOCH_TIMESTAMP = 11644473600  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
def dt_to_filetime(dt): # dt.timestamp() returns UTC time as expected by the LDAP server
	return int((dt.timestamp() + EPOCH_TIMESTAMP) * HUNDREDS_OF_NANOSECONDS)
def filetime_to_dt(ft): # ft is in UTC, fromtimestamp() converts to local time
	return datetime.fromtimestamp(int((ft / HUNDREDS_OF_NANOSECONDS) - EPOCH_TIMESTAMP))


class LapsAboutWindow(QDialog):
	def __init__(self, *args, **kwargs):
		super(LapsAboutWindow, self).__init__(*args, **kwargs)
		self.InitUI()

	def InitUI(self):
		self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
		self.buttonBox.accepted.connect(self.accept)

		self.layout = QVBoxLayout(self)

		labelAppName = QLabel(self)
		labelAppName.setText(self.parentWidget().PRODUCT_NAME + " v" + self.parentWidget().PRODUCT_VERSION)
		labelAppName.setStyleSheet("font-weight:bold")
		labelAppName.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelAppName)

		labelCopyright = QLabel(self)
		labelCopyright.setText(
			"<br>"
			"© 2021 <a href='https://github.com/schorschii'>Georg Sieber</a>"
			"<br>"
			"<br>"
			"GNU General Public License v3.0"
			"<br>"
			"<a href='"+self.parentWidget().PRODUCT_WEBSITE+"'>"+self.parentWidget().PRODUCT_WEBSITE+"</a>"
			"<br>"
		)
		labelCopyright.setOpenExternalLinks(True)
		labelCopyright.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelCopyright)

		labelDescription = QLabel(self)
		labelDescription.setText(
			"""LAPS4LINUX GUI allows you to query local administrator passwords for workstations in you domain running the LAPS client from your LDAP (Active Directory) server.\n\n"""
			"""The LAPS client periodically sets a new administrator password and saves it into the LDAP directory.\n\n"""
			"""LAPS was originally developed by Microsoft, this is an inofficial Linux implementation."""
		)
		labelDescription.setStyleSheet("opacity:0.8")
		labelDescription.setFixedWidth(450)
		labelDescription.setWordWrap(True)
		self.layout.addWidget(labelDescription)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle("About")

class LapsMainWindow(QMainWindow):
	PRODUCT_NAME      = 'LAPS4LINUX'
	PRODUCT_VERSION   = '1.1.0'
	PRODUCT_WEBSITE   = 'https://georg-sieber.de'

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
		aboutAction.triggered.connect(self.OnOpenAboutDialog)
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
		self.setWindowTitle(self.PRODUCT_NAME+' v'+self.PRODUCT_VERSION)

		# Show Note
		if not 'slub' in self.cfgDomain:
			self.statusBar.showMessage('If you like LAPS4LINUX please consider making a donation to support further development ('+self.PRODUCT_WEBSITE+').')

	def OnQuit(self, e):
		sys.exit()

	def OnOpenAboutDialog(self, e):
		dlg = LapsAboutWindow(self)
		dlg.exec_()

	def OnReturnSearch(self):
		self.OnClickSearch(None)

	def OnClickSearch(self, e):
		# check and escape input
		computerName = self.txtSearchComputer.text()
		if computerName.strip() == "": return
		computerName = utils.conv.escape_filter_chars(computerName)

		# ask for credentials
		self.btnSearchComputer.setEnabled(False)
		if not self.checkCredentialsAndConnect():
			self.btnSearchComputer.setEnabled(True)
			return

		try:
			# start LDAP query
			self.connection.search(search_base=self.createLdapBase(self.cfgDomain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+computerName+'))',attributes=['ms-MCS-AdmPwd','ms-MCS-AdmPwdExpirationTime','SAMAccountname','distinguishedName'])
			for entry in self.connection.entries:
				# display result
				print('expiration time:     '+str(entry['ms-Mcs-AdmPwdExpirationTime']))
				self.txtPassword.setText(str(entry['ms-Mcs-AdmPwd']))
				self.txtPasswordExpires.setText(str(entry['ms-Mcs-AdmPwdExpirationTime']))
				self.statusBar.showMessage('Found: '+str(entry['distinguishedName'])+' ('+self.cfgServer+':'+str(self.cfgPort)+' '+self.cfgUsername+'@'+self.cfgDomain+')')
				self.tmpDn = str(entry['distinguishedName'])
				self.btnSetExpirationTime.setEnabled(True)
				self.btnSearchComputer.setEnabled(True)
				try:
					self.txtPasswordExpires.setText( str(filetime_to_dt( int(str(entry['ms-Mcs-AdmPwdExpirationTime'])) )) )
				except Exception as e: print(str(e))
				return

			# no result found
			self.txtPassword.setText('')
			self.txtPasswordExpires.setText('')
			self.statusBar.showMessage('No Result For: '+computerName+' ('+self.cfgServer+':'+str(self.cfgPort)+' '+self.cfgUsername+'@'+self.cfgDomain+')')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			# reset connection
			self.server = None
			self.connection = None

		self.tmpDn = ''
		self.btnSetExpirationTime.setEnabled(False)
		self.btnSearchComputer.setEnabled(True)

	def OnClickSetExpiry(self, e):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		# ask for credentials
		if not self.checkCredentialsAndConnect(): return

		try:
			# calc new time
			newExpirationDateTime = dt_to_filetime( datetime.combine(self.cwNewExpirationTime.selectedDate().toPyDate(), datetime.min.time()) )
			print('new expiration time: '+str(newExpirationDateTime))

			# start LDAP query
			self.connection.modify(self.tmpDn, { 'ms-Mcs-AdmPwdExpirationTime': [(MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if self.connection.result['result'] == 0:
				self.statusBar.showMessage('Expiration Date Changed Successfully: '+self.tmpDn+' ('+self.cfgServer+':'+str(self.cfgPort)+' '+self.cfgUsername+'@'+self.cfgDomain+')')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			# reset connection
			self.server = None
			self.connection = None

	def checkCredentialsAndConnect(self):
		if self.server != None and self.connection != None: return True

		# ask for server address and domain name if not already set via config file
		if self.cfgServer == "":
			item, ok = QInputDialog.getText(self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
			if ok and item:
				self.cfgServer = item
				self.server = None
			else: return False
		if self.cfgDomain == "":
			item, ok = QInputDialog.getText(self, '♕ Domain', 'Please enter your Domain name (e.g. example.com).')
			if ok and item:
				self.cfgDomain = item
				self.server = None
			else: return False
		self.SaveSettings()

		# establish server connection
		if self.server == None:
			try:
				self.server = Server(self.cfgServer, port=self.cfgPort, use_ssl=self.cfgSsl, get_info=ALL)
			except Exception as e:
				self.showErrorDialog('Error connecting to LDAP server', str(e))
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
			item, ok = QInputDialog.getText(self, '👤 Username', 'Please enter the username which should be used to connect to »'+self.cfgServer+'«.', QLineEdit.Normal, getpass.getuser())
			if ok and item:
				self.cfgUsername = item
				self.connection = None
			else: return False
		if self.cfgPassword == "":
			item, ok = QInputDialog.getText(self, '🔑 Password for »'+self.cfgUsername+'«', 'Please enter the password which should be used to connect to »'+self.cfgServer+'«.', QLineEdit.Password)
			if ok and item:
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
			self.showErrorDialog('Error binding to LDAP server', str(e))
			return False

		return True # return if connection created successfully

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
			self.showErrorDialog('Error loading settings file', str(e))

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
			self.showErrorDialog('Error saving settings file', str(e))

	def showErrorDialog(self, title, text):
		print('Error: '+text)
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Critical)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setStandardButtons(QMessageBox.Ok)
		retval = msg.exec_()

def main():
	app = QApplication(sys.argv)
	window = LapsMainWindow()
	window.show()
	sys.exit(app.exec_())

if __name__ == '__main__':
	main()
