#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

from urllib.parse import unquote
from pathlib import Path
from os import path, makedirs, rename
from datetime import datetime
from dns import resolver, rdatatype
import ldap3
import ssl
import getpass
import json
import sys
import os


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
		labelAppName.setText(self.parentWidget().PRODUCT_NAME + ' v' + self.parentWidget().PRODUCT_VERSION)
		labelAppName.setStyleSheet('font-weight:bold')
		labelAppName.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelAppName)

		labelCopyright = QLabel(self)
		labelCopyright.setText(
			'<br>'
			'© 2021-2023 <a href="https://georg-sieber.de">Georg Sieber</a>'
			'<br>'
			'<br>'
			'GNU General Public License v3.0'
			'<br>'
			'<a href="'+self.parentWidget().PRODUCT_WEBSITE+'">'+self.parentWidget().PRODUCT_WEBSITE+'</a>'
			'<br>'
			'<br>'
			'If you like LAPS4LINUX please consider<br>making a donation to support further development.'
			'<br>'
		)
		labelCopyright.setOpenExternalLinks(True)
		labelCopyright.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelCopyright)

		labelDescription = QLabel(self)
		labelDescription.setText(
			'LAPS4LINUX client allows you to query local administrator passwords for LAPS runner managed workstations in your domain from your LDAP (Active Directory) server.'
			'\n\n'
			'The LAPS runner periodically sets a new administrator password and saves it into the LDAP directory.'
			'\n\n'
			'LAPS was originally developed by Microsoft, this is an inofficial Linux/Unix implementation with some enhancements (e.g. the CLI/GUI client can display additional attributes).'
		)
		labelDescription.setStyleSheet('opacity:0.8')
		labelDescription.setFixedWidth(450)
		labelDescription.setWordWrap(True)
		self.layout.addWidget(labelDescription)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle('About')

class LapsCalendarWindow(QDialog):
	def __init__(self, *args, **kwargs):
		super(LapsCalendarWindow, self).__init__(*args, **kwargs)
		self.InitUI()

	def InitUI(self):
		self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel)
		self.buttonBox.accepted.connect(self.OnClickAccept)
		self.buttonBox.rejected.connect(self.OnClickReject)

		self.layout = QVBoxLayout(self)

		self.cwNewExpirationTime = QCalendarWidget()
		self.layout.addWidget(self.cwNewExpirationTime)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle('Set New Expiration Date')

	def OnClickAccept(self):
		parentWidget = self.parentWidget()

		# check if dn of target computer object is known
		if parentWidget.tmpDn.strip() == '': return

		try:
			# calc new time
			newExpirationDate = datetime.combine(self.cwNewExpirationTime.selectedDate().toPyDate(), datetime.min.time())
			newExpirationDateTime = dt_to_filetime(newExpirationDate)
			print('new expiration time: '+str(newExpirationDateTime))

			# start LDAP modify
			parentWidget.connection.modify(parentWidget.tmpDn, { parentWidget.cfgLdapAttributePasswordExpiry: [(ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if parentWidget.connection.result['result'] == 0:
				parentWidget.showInfoDialog('Success',
					'Expiration date successfully changed to '+str(newExpirationDate)+'.',
					parentWidget.tmpDn+' ('+parentWidget.GetConnectionString()+')'
				)
				# update values in main window
				parentWidget.OnClickSearch(None)
				self.close()
			else:
				parentWidget.showErrorDialog('Error',
					'Unable to change expiration date to '+str(newExpirationDateTime)+'.'
					+'\n\n'+str(parentWidget.connection.result['message']), parentWidget.tmpDn+' ('+parentWidget.GetConnectionString()+')'
				)

		except Exception as e:
			# display error
			parentWidget.showErrorDialog('Error setting new expiration date', str(e))
			# reset connection
			parentWidget.server = None
			parentWidget.connection = None

	def OnClickReject(self):
		self.close()

class LapsMainWindow(QMainWindow):
	PLATFORM          = sys.platform.lower()

	PRODUCT_NAME      = 'LAPS4WINDOWS' if PLATFORM=='win32' else 'LAPS4MAC' if PLATFORM=='darwin' else 'LAPS4LINUX'
	PRODUCT_VERSION   = '1.5.2'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/laps4linux'
	PROTOCOL_SCHEME   = 'laps://'
	PRODUCT_ICON      = 'laps.png'
	PRODUCT_ICON_PATH = '/usr/share/pixmaps'

	tlsSettings = ldap3.Tls(validate=ssl.CERT_REQUIRED)

	gcModeOn    = False
	server      = None
	connection  = None
	tmpDn       = ''

	cfgPresetDirWindows = path.dirname(sys.executable) if getattr(sys, 'frozen', False) else sys.path[0]
	cfgPresetDirUnix    = '/etc'
	cfgPresetFile       = 'laps-client.json'
	cfgPresetPath       = (cfgPresetDirWindows if PLATFORM=='win32' else cfgPresetDirUnix)+'/'+cfgPresetFile

	cfgDir         = str(Path.home())+'/.config/laps-client'
	cfgPath        = cfgDir+'/settings.json'
	cfgPathRemmina = cfgDir+'/laps.remmina'
	cfgPathOld     = str(Path.home())+'/.laps-client.json'
	cfgUseKerberos = True
	cfgUseStartTls = True
	cfgServer      = []
	cfgDomain      = None
	cfgUsername    = ''
	cfgPassword    = ''
	cfgLdapAttributes              = {
		'Administrator Password':   'ms-Mcs-AdmPwd',
		'Password Expiration Date': 'ms-Mcs-AdmPwdExpirationTime'
	}
	cfgLdapAttributePassword       = 'ms-Mcs-AdmPwd'
	cfgLdapAttributePasswordExpiry = 'ms-Mcs-AdmPwdExpirationTime'
	refLdapAttributesTextBoxes     = {}


	def __init__(self):
		super(LapsMainWindow, self).__init__()
		self.LoadSettings()
		self.InitUI()

	def InitUI(self):
		# Icon Selection
		if(getattr(sys, 'frozen', False)):
			# included via pyinstaller (Windows & macOS)
			self.PRODUCT_ICON_PATH = sys._MEIPASS
		self.iconPath = path.join(self.PRODUCT_ICON_PATH, self.PRODUCT_ICON)
		if(path.exists(self.iconPath)):
			self.icon = QIcon(self.iconPath)
			self.setWindowIcon(self.icon)

		# Menubar
		mainMenu = self.menuBar()

		# File Menu
		fileMenu = mainMenu.addMenu('&File')

		searchAction = QAction('&Search', self)
		searchAction.setShortcut('F2')
		searchAction.triggered.connect(self.OnClickSearch)
		fileMenu.addAction(searchAction)
		if(self.cfgLdapAttributePasswordExpiry.strip() != ''):
			setExpirationDateAction = QAction('Set &Expiration', self)
			setExpirationDateAction.setShortcut('F3')
			setExpirationDateAction.triggered.connect(self.OnClickSetExpiry)
			fileMenu.addAction(setExpirationDateAction)
		fileMenu.addSeparator()
		kerberosAction = QAction('&Kerberos Authentication', self)
		kerberosAction.setShortcut('Ctrl+K')
		kerberosAction.setCheckable(True)
		kerberosAction.setChecked(self.cfgUseKerberos)
		kerberosAction.triggered.connect(self.OnClickKerberos)
		fileMenu.addAction(kerberosAction)
		fileMenu.addSeparator()
		quitAction = QAction('&Quit', self)
		quitAction.setShortcut('Ctrl+Q')
		quitAction.triggered.connect(self.OnQuit)
		fileMenu.addAction(quitAction)

		# Connection Menu
		# only available on linux as there is no reasonable way to open remote connections with password on other OSes
		if(self.PLATFORM == 'linux'):
			connectMenu = mainMenu.addMenu('&Connect')

			rdpAction = QAction('&RDP', self)
			rdpAction.setShortcut('F5')
			rdpAction.triggered.connect(self.OnClickRDP)
			connectMenu.addAction(rdpAction)
			sshAction = QAction('&SSH', self)
			sshAction.setShortcut('F6')
			sshAction.triggered.connect(self.OnClickSSH)
			connectMenu.addAction(sshAction)

		# Help Menu
		helpMenu = mainMenu.addMenu('&Help')

		aboutAction = QAction('&About', self)
		aboutAction.setShortcut('F1')
		aboutAction.triggered.connect(self.OnOpenAboutDialog)
		helpMenu.addAction(aboutAction)

		# Statusbar
		self.statusBar = self.statusBar()

		# Window Content
		grid = QGridLayout()
		gridLine = 0

		self.lblSearchComputer = QLabel('Computer Name')
		grid.addWidget(self.lblSearchComputer, gridLine, 0)
		gridLine += 1
		self.txtSearchComputer = QLineEdit()
		self.txtSearchComputer.returnPressed.connect(self.OnReturnSearch)
		grid.addWidget(self.txtSearchComputer, gridLine, 0)
		self.btnSearchComputer = QPushButton('Search')
		self.btnSearchComputer.clicked.connect(self.OnClickSearch)
		grid.addWidget(self.btnSearchComputer, gridLine, 1)
		gridLine += 1

		for title, attribute in self.GetAttributesAsDict().items():
			lblAdditionalAttribute = QLabel(str(title))
			grid.addWidget(lblAdditionalAttribute, gridLine, 0)
			gridLine += 1
			txtAdditionalAttribute = QLineEdit()
			txtAdditionalAttribute.setReadOnly(True)
			if(self.PLATFORM=='win32'):
				font = QFont('Consolas', 14)
				font.setBold(True)
			else:
				font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
				font.setPointSize(18 if self.PLATFORM=='darwin' else 14)
			txtAdditionalAttribute.setFont(font)
			grid.addWidget(txtAdditionalAttribute, gridLine, 0)
			gridLine += 1
			self.refLdapAttributesTextBoxes[str(title)] = txtAdditionalAttribute

		self.btnSetExpirationTime = QPushButton('Set New Expiration Date')
		self.btnSetExpirationTime.setEnabled(False)
		self.btnSetExpirationTime.clicked.connect(self.OnClickSetExpiry)
		if(self.cfgLdapAttributePasswordExpiry.strip() != ''):
			grid.addWidget(self.btnSetExpirationTime, gridLine, 0)
			gridLine += 1

		widget = QWidget(self)
		widget.setLayout(grid)
		self.setCentralWidget(widget)

		# Window Settings
		self.setMinimumSize(480, 300)
		self.setWindowTitle(self.PRODUCT_NAME)
		self.statusBar.showMessage('Settings file: '+self.cfgPath)

		# Handle Parameter - Automatic Search
		urlToHandle = None
		for arg in sys.argv:
			if(arg.startswith(self.PROTOCOL_SCHEME)):
				urlToHandle = arg
		if(urlToHandle != None):
			print('Handle '+urlToHandle)
			protocolPayload = unquote(urlToHandle).replace(self.PROTOCOL_SCHEME, '').strip(' /')
			self.txtSearchComputer.setText(protocolPayload)
			self.OnClickSearch(None)

	def GetAttributesAsDict(self):
		finalDict = {}
		if(isinstance(self.cfgLdapAttributes, list)):
			for attribute in self.cfgLdapAttributes:
				finalDict[attribute] = attribute
		elif(isinstance(self.cfgLdapAttributes, dict)):
			for title, attribute in self.cfgLdapAttributes.items():
				finalDict[str(title)] = str(attribute)
		return finalDict

	def OnQuit(self, e):
		sys.exit()

	def OnClickKerberos(self, e):
		self.cfgUseKerberos = not self.cfgUseKerberos

	def OnOpenAboutDialog(self, e):
		dlg = LapsAboutWindow(self)
		dlg.exec_()

	def OnReturnSearch(self):
		self.OnClickSearch(None)

	def OnClickRDP(self, e):
		self.RemoteConnection('RDP')

	def OnClickSSH(self, e):
		self.RemoteConnection('SSH')

	def RemoteConnection(self, protocol):
		if(self.txtSearchComputer.text().strip() == ''): return

		try:
			import subprocess
			import time
			import configparser
			import base64
			from shutil import which
			from Crypto.Cipher import DES3

			password = ''
			for title, attribute in self.GetAttributesAsDict().items():
				if(self.cfgLdapAttributePassword == attribute):
					if(title in self.refLdapAttributesTextBoxes):
						password = self.refLdapAttributesTextBoxes[title].text()

			if(which('remmina') is None): raise Exception('Remmina is not installed')
			# passwords must be encrypted in remmina connection files using the secret found in remmina.pref
			remminaPrefPath = str(Path.home())+'/.remmina/remmina.pref'
			if(os.path.exists(remminaPrefPath)):
				config = configparser.ConfigParser()
				config.read(remminaPrefPath)
				if(config.has_section('remmina_pref') and 'secret' in config['remmina_pref'] and config['remmina_pref']['secret'].strip() != ''):
					secret = base64.b64decode(config['remmina_pref']['secret'])
					padding = chr(0) * (8 - len(password) % 8)
					password = base64.b64encode( DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).encrypt(password+padding) ).decode('utf-8')
				else:
					password = ''
					self.statusBar.showMessage('Unable to find secret in remmina_pref')
			else:
				password = ''
				self.statusBar.showMessage('Unable to find remmina.pref')

			# creating remmina files with permissions 400 is currently useless as remmina re-creates the file with 664 on exit with updated settings
			# protection is done by limiting access to our config dir
			if(protocol == 'RDP'):
				with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						'[remmina]\n'+
						'name='+self.txtSearchComputer.text()+'\n'+
						'server='+self.txtSearchComputer.text()+'\n'+
						'username=administrator\n'+
						'password='+password+'\n'
						'protocol=RDP\n'+
						'scale=2\n'+
						'window_width=1092\n'+
						'window_height=720\n'+
						'colordepth=0\n'
					)
					f.close()
				time.sleep(0.2)
			elif(protocol == 'SSH'):
				with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						'[remmina]\n'+
						'name='+self.txtSearchComputer.text()+'\n'+
						'server='+self.txtSearchComputer.text()+'\n'+
						'username=administrator\n'+
						'password='+password+'\n'
						'protocol=SSH\n'
					)
					f.close()
				time.sleep(0.2)
			subprocess.Popen(['remmina', '-c', self.cfgPathRemmina])
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			print(str(e))

	def OnClickSearch(self, e):
		# check and escape input
		computerName = self.txtSearchComputer.text()
		if computerName.strip() == '': return
		computerName = ldap3.utils.conv.escape_filter_chars(computerName)

		# ask for credentials
		self.btnSearchComputer.setEnabled(False)
		if not self.checkCredentialsAndConnect():
			self.btnSearchComputer.setEnabled(True)
			return

		try:
			# start LDAP search
			self.connection.search(
				search_base=self.createLdapBase(self.connection),
				search_filter='(&(objectCategory=computer)(name='+computerName+'))',
				attributes=['SAMAccountname', 'distinguishedName']
			)
			for entry in self.connection.entries:
				self.statusBar.showMessage('Found: '+str(entry['distinguishedName'])+' ('+self.GetConnectionString()+')')
				self.setWindowTitle(str(entry['SAMAccountname'])+' - '+self.PRODUCT_NAME)
				self.tmpDn = str(entry['distinguishedName'])
				self.queryAttributes()
				return

			# no result found
			self.statusBar.showMessage('No Result For: '+computerName+' ('+self.GetConnectionString()+')')
			for title, attribute in self.GetAttributesAsDict().items():
				self.refLdapAttributesTextBoxes[str(title)].setText('')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			print(str(e))
			# reset connection
			self.server = None
			self.connection = None

		self.tmpDn = ''
		self.btnSetExpirationTime.setEnabled(False)
		self.btnSearchComputer.setEnabled(True)

	def OnClickSetExpiry(self, e):
		# check if dn of target computer object is known
		if self.tmpDn.strip() == '': return

		dlg = LapsCalendarWindow(self)
		dlg.refMainWindows = self
		dlg.exec_()

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
		# display result
		for entry in self.connection.entries:
			self.btnSetExpirationTime.setEnabled(True)
			self.btnSearchComputer.setEnabled(True)
			for title, attribute in self.GetAttributesAsDict().items():
				textBox = self.refLdapAttributesTextBoxes[str(title)]
				if(str(attribute) == self.cfgLdapAttributePasswordExpiry):
					try:
						textBox.setText( str(filetime_to_dt( int(str(entry[str(attribute)])) )) )
					except Exception as e:
						print(str(e))
						textBox.setText( str(entry[str(attribute)]) )
				else:
					textBox.setText( str(entry[str(attribute)]) )
			return

	def checkCredentialsAndConnect(self):
		# ask for server address and domain name if not already set via config file
		if self.cfgDomain == None:
			item, ok = QInputDialog.getText(self, '♕ Domain', 'Please enter your Domain name (e.g. example.com, leave empty to try auto discovery).')
			if ok and item != None:
				self.cfgDomain = item
				self.server = None
		if len(self.cfgServer) == 0:
			# query domain controllers by dns lookup
			searchDomain = '.'+self.cfgDomain if self.cfgDomain!='' else ''
			try:
				res = resolver.resolve(qname='_ldap._tcp'+searchDomain, rdtype=rdatatype.SRV, lifetime=10, search=True)
				for srv in res.rrset:
					serverEntry = {
						# strip the trailing . from the dns resolver for certificate verification reasons.
						'address': str(srv.target).rstrip('.'),
						'port': srv.port,
						'ssl': (srv.port == 636),
						'auto-discovered': True
					}
					print('DNS auto discovery found server: '+json.dumps(serverEntry))
					self.cfgServer.append(serverEntry)
			except Exception as e: print('DNS auto discovery failed: '+str(e))
			# ask user to enter server names if auto discovery was not successful
			if len(self.cfgServer) == 0:
				item, ok = QInputDialog.getText(self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
				if ok and item:
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
					serverArray.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], tls=self.tlsSettings, get_info=ldap3.ALL))
				self.server = ldap3.ServerPool(serverArray, ldap3.FIRST, active=True, exhaust=True)
			except Exception as e:
				self.showErrorDialog('Error connecting to LDAP server', str(e))
				return False

		# try to bind to server via Kerberos
		try:
			if(self.cfgUseKerberos):
				self.connection = ldap3.Connection(
					self.server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
				)
				if(self.cfgUseStartTls): self.connection.start_tls()
				return True # return if connection created successfully
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))

		# ask for username and password for SIMPLE bind
		if self.cfgUsername == '':
			item, ok = QInputDialog.getText(self, '👤 Username', 'Please enter the username which should be used to connect to:\n'+str(self.cfgServer), QLineEdit.Normal, getpass.getuser())
			if ok and item:
				self.cfgUsername = item
				self.connection = None
			else: return False
		if self.cfgPassword == '':
			item, ok = QInputDialog.getText(self, '🔑 Password for »'+self.cfgUsername+'«', 'Please enter the password which should be used to connect to:\n'+str(self.cfgServer), QLineEdit.Password)
			if ok and item:
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
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
			)
			if(self.cfgUseStartTls): self.connection.start_tls()
		except Exception as e:
			self.cfgUsername = ''
			self.cfgPassword = ''
			self.showErrorDialog('Error binding to LDAP server', str(e))
			return False

		return True # return if connection created successfully

	def reconnectForAttributeQuery(self):
		# global catalog was not used for search - we can use the same connection for attribute query
		if(not self.gcModeOn): return True
		# global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
		# -> that's why we need to establish a new connection to the "normal" LDAP port
		# LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
		serverArray = []
		for server in self.cfgServer:
			serverArray.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], tls=self.tlsSettings, get_info=ldap3.ALL))
		server = ldap3.ServerPool(serverArray, ldap3.FIRST, active=True, exhaust=True)
		# try to bind to server via Kerberos
		try:
			if(self.cfgUseKerberos):
				self.connection = ldap3.Connection(server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
				)
				if(self.cfgUseStartTls): self.connection.start_tls()
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
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
			)
			if(self.cfgUseStartTls): self.connection.start_tls()
			return True
		except Exception as e:
			self.showErrorDialog('Error binding to LDAP server', str(e))
			return False

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
		if(not path.isdir(self.cfgDir)):
			makedirs(self.cfgDir, exist_ok=True)
		# protect temporary .remmina file by limiting access to our config folder
		if(self.PLATFORM == 'linux'): os.chmod(self.cfgDir, 0o700)
		if(path.exists(self.cfgPathOld)):
			rename(self.cfgPathOld, self.cfgPath)

		if(path.isfile(self.cfgPath)): cfgPath = self.cfgPath
		elif(path.isfile(self.cfgPresetPath)): cfgPath = self.cfgPresetPath
		else: return

		try:
			with open(cfgPath) as f:
				cfgJson = json.load(f)
				self.cfgUseKerberos = cfgJson.get('use-kerberos', self.cfgUseKerberos)
				self.cfgUseStartTls = cfgJson.get('use-starttls', self.cfgUseStartTls)
				self.cfgServer = cfgJson.get('server', self.cfgServer)
				self.cfgDomain = cfgJson.get('domain', self.cfgDomain)
				self.cfgUsername = cfgJson.get('username', self.cfgUsername)
				self.cfgLdapAttributePassword = str(cfgJson.get('ldap-attribute-password', self.cfgLdapAttributePassword))
				self.cfgLdapAttributePasswordExpiry = str(cfgJson.get('ldap-attribute-password-expiry', self.cfgLdapAttributePasswordExpiry))
				tmpLdapAttributes = cfgJson.get('ldap-attributes', self.cfgLdapAttributes)
				if(isinstance(tmpLdapAttributes, list) or isinstance(tmpLdapAttributes, dict)):
					self.cfgLdapAttributes = tmpLdapAttributes
		except Exception as e:
			self.showErrorDialog('Error loading settings file', str(e))

	def SaveSettings(self):
		try:
			# do not save auto-discovered servers to config - should be queried every time
			saveServers = []
			for server in self.cfgServer:
				if not server.get('auto-discovered', False):
					saveServers.append(server)

			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'use-kerberos': self.cfgUseKerberos,
					'use-starttls': self.cfgUseStartTls,
					'server': saveServers,
					'domain': self.cfgDomain,
					'username': self.cfgUsername,
					'ldap-attribute-password': self.cfgLdapAttributePassword,
					'ldap-attribute-password-expiry': self.cfgLdapAttributePasswordExpiry,
					'ldap-attributes': self.cfgLdapAttributes
				}, json_file, indent=4)
		except Exception as e:
			self.showErrorDialog('Error saving settings file', str(e))

	def showErrorDialog(self, title, text, additionalText=''):
		print('Error: '+text)
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Critical)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additionalText)
		msg.setStandardButtons(QMessageBox.Ok)
		retval = msg.exec_()
	def showInfoDialog(self, title, text, additionalText=''):
		print('Info: '+text)
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Information)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additionalText)
		msg.setStandardButtons(QMessageBox.Ok)
		retval = msg.exec_()

def main():
	app = QApplication(sys.argv)
	window = LapsMainWindow()
	window.show()
	sys.exit(app.exec_())

if __name__ == '__main__':
	main()
