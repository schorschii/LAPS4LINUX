#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .__init__ import __title__, __version__, __website__, __author__, __copyright__
from .__init__ import proposeUsername, compileServerUris
from .filetime import dt_to_filetime, filetime_to_dt

from PyQt6 import QtWidgets, QtGui, QtCore

from urllib.parse import unquote
from pathlib import Path
from os import path, makedirs, rename
from datetime import datetime
from dns import resolver, rdatatype
from functools import partial
import traceback
import dpapi_ng
import ldap3
import ssl
import json
import sys
import os


class LapsAboutWindow(QtWidgets.QDialog):
	def __init__(self, *args, **kwargs):
		super(LapsAboutWindow, self).__init__(*args, **kwargs)
		self.InitUI()

	def InitUI(self):
		self.buttonBox = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok)
		self.buttonBox.accepted.connect(self.accept)

		self.layout = QtWidgets.QVBoxLayout(self)

		labelAppName = QtWidgets.QLabel(self)
		labelAppName.setText(__title__ + ' GUI Client' + ' v' + __version__)
		labelAppName.setStyleSheet('font-weight:bold')
		labelAppName.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(labelAppName)

		labelCopyright = QtWidgets.QLabel(self)
		labelCopyright.setText(
			'<br>'
			+__copyright__+' <a href="https://georg-sieber.de">'+__author__+'</a>'
			'<br>'
			'<br>'
			'GNU General Public License v3.0'
			'<br>'
			'<a href="'+__website__+'">'+__website__+'</a>'
			'<br>'
			'<br>'
			'If you like LAPS4LINUX please consider<br>making a donation to support further development.'
			'<br>'
		)
		labelCopyright.setOpenExternalLinks(True)
		labelCopyright.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(labelCopyright)

		labelDescription = QtWidgets.QLabel(self)
		labelDescription.setText(
			'LAPS4LINUX client allows you to query local administrator passwords for LAPS runner managed workstations in your domain from your LDAP (Active Directory) server.'
			'\n\n'
			'The LAPS runner periodically sets a new administrator password and saves it into the LDAP directory.'
			'\n\n'
			'LAPS was originally developed by Microsoft, this is an unofficial Linux/Unix implementation with some enhancements (e.g. the CLI/GUI client can display additional attributes).'
		)
		labelDescription.setFixedWidth(450)
		labelDescription.setWordWrap(True)
		self.layout.addWidget(labelDescription)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle('About')

class LapsLoginWindow(QtWidgets.QDialog):
	def __init__(self, server, username, *args, **kwargs):
		super(LapsLoginWindow, self).__init__(*args, **kwargs)

		# window layout
		self.buttonBox = QtWidgets.QDialogButtonBox(
			QtWidgets.QDialogButtonBox.StandardButton.Ok
			| QtWidgets.QDialogButtonBox.StandardButton.Cancel
		)
		self.buttonBox.accepted.connect(self.accept)
		self.buttonBox.rejected.connect(self.reject)

		self.layout = QtWidgets.QGridLayout(self)

		self.lblDescription = QtWidgets.QLabel('Please enter the credentials which should be used to connect to:\n'+server)
		self.layout.addWidget(self.lblDescription, 0, 0, 1, 2)

		self.lblUsername = QtWidgets.QLabel('Username')
		self.layout.addWidget(self.lblUsername, 1, 0)
		self.txtUsername = QtWidgets.QLineEdit()
		self.txtUsername.setText(username)
		self.layout.addWidget(self.txtUsername, 1, 1, 1, 2)

		self.lblPassword = QtWidgets.QLabel('Password')
		self.layout.addWidget(self.lblPassword, 2, 0)
		self.txtPassword = QtWidgets.QLineEdit()
		self.txtPassword.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
		self.layout.addWidget(self.txtPassword, 2, 1, 1, 2)

		self.layout.addWidget(self.buttonBox, 3, 1, 1, 2)
		self.setLayout(self.layout)

		# window properties
		self.setWindowTitle('LDAP Bind Credentials')
		self.resize(350, 150)
		#self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)

		if(self.txtUsername.text() != ''):
			self.txtPassword.setFocus()

class LapsBarcodeWindow(QtWidgets.QDialog):
	def __init__(self, title, value, img, *args, **kwargs):
		super(LapsBarcodeWindow, self).__init__(*args, **kwargs)
		self.title = title
		self.value = value
		self.img = img
		self.InitUI()

	def InitUI(self):
		parentWidget = self.parentWidget()

		# Menubar
		mainMenu = QtWidgets.QMenuBar(self)
		fileMenu = mainMenu.addMenu('&File')
		saveAction = QtGui.QAction('&Save image', self)
		saveAction.setShortcut('F2')
		saveAction.triggered.connect(self.OnClickSave)
		fileMenu.addAction(saveAction)
		fileMenu.addSeparator()
		closeAction = QtGui.QAction('&Close', self)
		closeAction.triggered.connect(self.OnClickClose)
		fileMenu.addAction(closeAction)

		self.layout = QtWidgets.QVBoxLayout()
		self.layout.setContentsMargins(20, 50, 20, 20)

		if(self.img.mode == '1'):
			self.img = self.img.convert('RGBA')
		img_bytes = self.img.tobytes('raw', 'RGBA')
		labelImage = QtWidgets.QLabel(self)
		c = QtGui.QCursor(QtCore.Qt.CursorShape.BlankCursor)
		labelImage.setCursor(c)
		labelImage.setPixmap(QtGui.QPixmap.fromImage(QtGui.QImage(img_bytes, self.img.size[0], self.img.size[1], QtGui.QImage.Format.Format_RGBA8888)))
		labelImage.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(labelImage)

		labelText = QtWidgets.QLabel(self)
		labelText.setText(self.value)
		labelText.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		labelText.setFont(parentWidget.textBoxFont)
		self.layout.addWidget(labelText)

		self.setLayout(self.layout)
		self.setWindowTitle(self.title)

	def OnClickSave(self):
		fileName, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save image', self.title+'.png', 'PNG Files (*.png);;All Files (*.*)')
		if(fileName):
			self.img.save(fileName)

	def OnClickClose(self):
		self.close()

class LapsCalendarWindow(QtWidgets.QDialog):
	def __init__(self, *args, **kwargs):
		super(LapsCalendarWindow, self).__init__(*args, **kwargs)
		self.InitUI()

	def InitUI(self):
		self.buttonBox = QtWidgets.QDialogButtonBox(
			QtWidgets.QDialogButtonBox.StandardButton.Ok
			| QtWidgets.QDialogButtonBox.StandardButton.Cancel
		)
		self.buttonBox.accepted.connect(self.OnClickAccept)
		self.buttonBox.rejected.connect(self.OnClickReject)

		self.layout = QtWidgets.QVBoxLayout(self)

		self.cwNewExpirationTime = QtWidgets.QCalendarWidget()
		self.layout.addWidget(self.cwNewExpirationTime)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle('Set New Expiration Date')

	def OnClickAccept(self):
		parentWidget = self.parentWidget()

		# check if dn of target computer object is known
		if parentWidget.tmpDn.strip() == '': return

		try:
			if isinstance(parentWidget.cfgLdapAttributePasswordExpiry, list) and len(parentWidget.cfgLdapAttributePasswordExpiry) > 0:
				attributeExpirationDate = parentWidget.cfgLdapAttributePasswordExpiry[0]
			else:
				attributeExpirationDate = str(parentWidget.cfgLdapAttributePasswordExpiry)

			# calc new time
			newExpirationDate = datetime.combine(self.cwNewExpirationTime.selectedDate().toPyDate(), datetime.min.time())
			newExpirationDateTime = dt_to_filetime(newExpirationDate)
			print('new expiration time: '+str(newExpirationDateTime))

			# start LDAP modify
			parentWidget.connection.modify(parentWidget.tmpDn, { attributeExpirationDate: [(ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])] })
			if parentWidget.connection.result['result'] == 0:
				parentWidget.showInfoDialog('Success',
					'Expiration date successfully changed to '+str(newExpirationDate)+'.',
					parentWidget.tmpDn+' ('+parentWidget.GetConnectionString()+')'
				)
				# update values in main window
				parentWidget.OnClickSearch(None)
				self.close()
			else:
				parentWidget.showInfoDialog('Error',
					'Unable to change expiration date to '+str(newExpirationDateTime)+'.'
					+'\n\n'+str(parentWidget.connection.result['message']), parentWidget.tmpDn+' ('+parentWidget.GetConnectionString()+')',
					icon=QtWidgets.QMessageBox.Icon.Critical
				)

		except Exception as e:
			# display error
			parentWidget.showInfoDialog('Error setting new expiration date', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
			# reset connection
			parentWidget.server = None
			parentWidget.connection = None

	def OnClickReject(self):
		self.close()

class LapsPlainTextEdit(QtWidgets.QPlainTextEdit):
	# default sizeHint of (256,192) is too large for our password history
	def sizeHint(self):
		return QtCore.QSize(200, 90)

class LapsMainWindow(QtWidgets.QMainWindow):
	PLATFORM          = sys.platform.lower()

	PROTOCOL_SCHEME   = 'laps://'
	PRODUCT_ICON      = 'laps.png'
	PRODUCT_ICON_PATH = '/usr/share/pixmaps'

	tlsSettings = ldap3.Tls(validate=ssl.CERT_REQUIRED)

	gcModeOn    = False
	server      = None
	connection  = None
	tmpDn       = ''
	currentComputerName = ''

	cfgPresetDirWindows = path.dirname(sys.executable) if getattr(sys, 'frozen', False) else sys.path[0]
	cfgPresetDirUnix    = '/etc'
	cfgPresetFile       = 'laps-client.json'
	cfgPresetPath       = (cfgPresetDirWindows if PLATFORM=='win32' else cfgPresetDirUnix)+'/'+cfgPresetFile

	cfgDir         = str(Path.home())+'/.config/laps-client'
	cfgPath        = cfgDir+'/settings.json'
	cfgPathRemmina = cfgDir+'/laps.remmina'
	cfgVersion     = 0
	cfgUseKerberos = True
	cfgUseStartTls = True
	cfgServer      = []
	cfgDomain      = None
	cfgLdapQuery   = '(&(objectClass=computer)(cn=%1))'
	cfgUsername    = ''
	cfgPassword    = ''
	cfgLdapAttributes              = {
		'Operating System':               'operatingSystem',
		'Administrator Password':         ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd'],
		'Password Expiration Date':       ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'],
		'Administrator Password History': 'msLAPS-EncryptedPasswordHistory'
	}
	cfgLdapAttributePassword        = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd']
	cfgLdapAttributePasswordExpiry  = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
	cfgLdapAttributePasswordHistory = 'msLAPS-EncryptedPasswordHistory'
	cfgConnectUsername              = 'administrator'
	cfgUseAutotypeEnter             = False
	refLdapAttributesTextBoxes      = {}


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
			self.icon = QtGui.QIcon(self.iconPath)
			self.setWindowIcon(self.icon)

		# Menubar
		mainMenu = self.menuBar()

		# File Menu
		fileMenu = mainMenu.addMenu('&File')

		searchAction = QtGui.QAction('&Search', self)
		searchAction.setShortcut('F2')
		searchAction.triggered.connect(self.OnClickSearch)
		fileMenu.addAction(searchAction)
		if(self.cfgLdapAttributePasswordExpiry):
			setExpirationDateAction = QtGui.QAction('Set &Expiration', self)
			setExpirationDateAction.setShortcut('F3')
			setExpirationDateAction.triggered.connect(self.OnClickSetExpiry)
			fileMenu.addAction(setExpirationDateAction)
		fileMenu.addSeparator()
		kerberosAction = QtGui.QAction('&Kerberos Authentication', self)
		kerberosAction.setShortcut('Ctrl+K')
		kerberosAction.setCheckable(True)
		kerberosAction.setChecked(self.cfgUseKerberos)
		kerberosAction.triggered.connect(self.OnClickKerberos)
		fileMenu.addAction(kerberosAction)
		fileMenu.addSeparator()
		quitAction = QtGui.QAction('&Quit', self)
		quitAction.setShortcut('Ctrl+Q')
		quitAction.triggered.connect(self.OnQuit)
		fileMenu.addAction(quitAction)

		# Connection Menu
		connectMenu = mainMenu.addMenu('&Connect')

		rdpAction = QtGui.QAction('&RDP', self)
		rdpAction.setShortcut('F5')
		rdpAction.triggered.connect(lambda: self.RemoteConnection('RDP'))
		connectMenu.addAction(rdpAction)
		sshAction = QtGui.QAction('&SSH', self)
		sshAction.setShortcut('F6')
		sshAction.triggered.connect(lambda: self.RemoteConnection('SSH'))
		connectMenu.addAction(sshAction)
		connectMenu.addSeparator()
		autotypeCodeAction = QtGui.QAction('&Autotype QR code', self)
		autotypeCodeAction.setShortcut('F7')
		autotypeCodeAction.triggered.connect(self.OnClickAutotypeCode)
		connectMenu.addAction(autotypeCodeAction)
		autotypeSeparatorAction = QtGui.QAction('Enter instead of Tab', self)
		autotypeSeparatorAction.setCheckable(True)
		autotypeSeparatorAction.setChecked(self.cfgUseAutotypeEnter)
		autotypeSeparatorAction.triggered.connect(self.OnClickAutotypeEnter)
		connectMenu.addAction(autotypeSeparatorAction)

		# Help Menu
		helpMenu = mainMenu.addMenu('&Help')

		aboutAction = QtGui.QAction('&About', self)
		aboutAction.setShortcut('F1')
		aboutAction.triggered.connect(self.OnOpenAboutDialog)
		helpMenu.addAction(aboutAction)

		# Statusbar
		self.statusBar = self.statusBar()

		# Window Content
		grid = QtWidgets.QGridLayout()
		gridLine = 0

		self.lblSearchComputer = QtWidgets.QLabel('Computer Name')
		grid.addWidget(self.lblSearchComputer, gridLine, 0)
		gridLine += 1
		self.txtSearchComputer = QtWidgets.QLineEdit()
		self.txtSearchComputer.returnPressed.connect(self.OnReturnSearch)
		self.txtSearchComputer.contextMenuEvent = partial(self.OnContextMenu, self.txtSearchComputer)
		grid.addWidget(self.txtSearchComputer, gridLine, 0)
		self.btnSearchComputer = QtWidgets.QPushButton('Search')
		self.btnSearchComputer.clicked.connect(self.OnClickSearch)
		grid.addWidget(self.btnSearchComputer, gridLine, 1)
		gridLine += 1

		self.btnSetExpirationTime = QtWidgets.QPushButton('Set')
		self.btnSetExpirationTime.setEnabled(False)
		self.btnSetExpirationTime.clicked.connect(self.OnClickSetExpiry)

		for title, attribute in self.GetAttributesAsDict().items():
			# create label
			lblAdditionalAttribute = QtWidgets.QLabel(str(title))
			grid.addWidget(lblAdditionalAttribute, gridLine, 0)
			gridLine += 1

			# instantiate single or multiline textbox
			if(attribute == self.cfgLdapAttributePasswordHistory
			or (isinstance(self.cfgLdapAttributePasswordHistory, list) and attribute in self.cfgLdapAttributePasswordHistory)):
				txtAdditionalAttribute = LapsPlainTextEdit()
				txtAdditionalAttribute.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
			else:
				txtAdditionalAttribute = QtWidgets.QLineEdit()
			txtAdditionalAttribute.setReadOnly(True)
			txtAdditionalAttribute.contextMenuEvent = partial(self.OnContextMenu, txtAdditionalAttribute)

			# set easy readable font
			if(self.PLATFORM == 'win32'):
				self.textBoxFont = QtGui.QFont('Consolas', 14)
				self.textBoxFont.setBold(True)
			else:
				self.textBoxFont = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
				self.textBoxFont.setPointSize(18 if self.PLATFORM=='darwin' else 14)
			txtAdditionalAttribute.setFont(self.textBoxFont)

			# add textbox to layout
			grid.addWidget(txtAdditionalAttribute, gridLine, 0)
			self.refLdapAttributesTextBoxes[str(title)] = txtAdditionalAttribute

			# create copy/set button
			if(attribute == self.cfgLdapAttributePasswordExpiry
			or (isinstance(self.cfgLdapAttributePasswordExpiry, list) and attribute in self.cfgLdapAttributePasswordExpiry)):
				grid.addWidget(self.btnSetExpirationTime, gridLine, 1)
			else:
				btnCopy = QtWidgets.QPushButton('Copy')
				btnCopy.clicked.connect(partial(self.OnClickCopy, txtAdditionalAttribute))
				grid.addWidget(btnCopy, gridLine, 1)
			gridLine += 1

		widget = QtWidgets.QWidget(self)
		widget.setLayout(grid)
		self.setCentralWidget(widget)

		# Window Settings
		self.setMinimumSize(480, 300)
		self.setWindowTitle(__title__)
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
				finalDict[str(title)] = attribute
		return finalDict

	def OnQuit(self, e):
		sys.exit()

	def OnContextMenu(self, lineEdit, e):
		menu = lineEdit.createStandardContextMenu()
		qrAction = QtGui.QAction('Show as QR code', self)
		qrAction.triggered.connect(lambda: self.OnClickShowAsCode(lineEdit, 'qr'))
		menu.addAction(qrAction)
		barcodeAction = QtGui.QAction('Show as barcode', self)
		barcodeAction.triggered.connect(lambda: self.OnClickShowAsCode(lineEdit, 'barcode'))
		menu.addAction(barcodeAction)
		menu.exec(e.globalPos())

	def OnClickShowAsCode(self, lineEdit, code):
		if(isinstance(lineEdit, QtWidgets.QPlainTextEdit)):
			text = lineEdit.toPlainText()
		else:
			text = lineEdit.text()
		if(not text): return
		self.showCode(text, code)

	def OnClickCopy(self, lineEdit, e):
		if(isinstance(lineEdit, QtWidgets.QPlainTextEdit)):
			text = lineEdit.toPlainText()
		else:
			text = lineEdit.text()
		cb = QtWidgets.QApplication.clipboard()
		cb.clear(mode=QtGui.QClipboard.Mode.Clipboard)
		cb.setText(text, mode=QtGui.QClipboard.Mode.Clipboard)

	def OnClickKerberos(self, e):
		self.cfgUseKerberos = not self.cfgUseKerberos
		self.SaveSettings()

	def OnClickAutotypeEnter(self, e):
		self.cfgUseAutotypeEnter = not self.cfgUseAutotypeEnter
		self.SaveSettings()

	def OnOpenAboutDialog(self, e):
		dlg = LapsAboutWindow(self)
		dlg.exec()

	def OnReturnSearch(self):
		self.OnClickSearch(None)

	def OnClickAutotypeCode(self):
		separator = "\t"
		if(self.cfgUseAutotypeEnter):
			# for Linux login screens (lightdm etc.)
			separator = "\n"
		text = self.cfgConnectUsername + separator + self.getCurrentPassword()
		self.showCode(text, 'qr')

	def showCode(self, text, code):
		if(code == 'qr'):
			import qrcode
			img = qrcode.make(text).get_image()
		else:
			import barcode
			barcode.base.Barcode.default_writer_options['write_text'] = False
			img = barcode.Code128(text, writer=barcode.writer.ImageWriter()).render()
		if(img):
			dlg = LapsBarcodeWindow(self.currentComputerName, text, img, self)
			dlg.show()

	def versionTuple(self, v):
		return tuple(map(int, (v.split('.'))))

	def prepareEnvironment(self):
		# restore library search path for subprocess (modified by PyInstaller)
		# see https://pyinstaller.org/en/v6.9.0/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application
		sub_env = os.environ.copy()
		if('LD_LIBRARY_PATH_ORIG' in sub_env):
			sub_env['LD_LIBRARY_PATH'] = sub_env['LD_LIBRARY_PATH_ORIG']
		elif('LD_LIBRARY_PATH' in sub_env):
			del sub_env['LD_LIBRARY_PATH']
		return sub_env

	def getCurrentPassword(self):
		password = ''
		for title, attribute in self.GetAttributesAsDict().items():
			if((isinstance(self.cfgLdapAttributePassword, str) and isinstance(attribute, str) and attribute.upper() == self.cfgLdapAttributePassword.upper())
			or attribute == self.cfgLdapAttributePassword):
				if(title in self.refLdapAttributesTextBoxes):
					password = self.refLdapAttributesTextBoxes[title].text()
		return password

	def RemoteConnection(self, protocol):
		if(self.txtSearchComputer.text().strip() == ''):
			return

		# only available on linux as there is no reasonable way to open remote connections with password on other OSes
		if(self.PLATFORM != 'linux'):
			self.showInfoDialog('Nope.', 'Only available on non-shitty operating systems.', icon=QtWidgets.QMessageBox.Icon.Warning)
			return

		try:
			import subprocess, time
			from shutil import which

			# check remmina existence and version
			if(which('remmina') is None): raise Exception('Remmina is not installed')
			newRemmina = False
			res = subprocess.run('remmina --version | grep org.remmina.Remmina | cut -d- -f2 | cut -d"(" -f1 | xargs', shell=True, env=self.prepareEnvironment(), stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
			if(self.versionTuple(res.stdout.decode('utf-8')) >= self.versionTuple('1.4.25')):
				newRemmina = True

			# get current admin password
			password = self.getCurrentPassword()

			# passwords must be encrypted in old remmina connection files using the secret found in remmina.pref
			if(not newRemmina):
				import base64, configparser
				from Cryptodome.Cipher import DES3

				remminaPrefPath = str(Path.home())+'/.remmina/remmina.pref' # older remmina versions
				if(not os.path.exists(remminaPrefPath)): remminaPrefPath = str(Path.home())+'/.config/remmina/remmina.pref' # newer remmina versions
				if(os.path.exists(remminaPrefPath)):
					config = configparser.ConfigParser()
					config.read(remminaPrefPath)
					if(config.has_section('remmina_pref') and 'secret' in config['remmina_pref'] and config['remmina_pref']['secret'].strip() != ''):
						secret = base64.b64decode(config['remmina_pref']['secret'])
						padding = chr(0) * (8 - len(password) % 8)
						password = base64.b64encode( DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).encrypt((password+padding).encode("utf8")) ).decode('utf-8')
					else:
						password = ''
						self.statusBar.showMessage('Unable to find secret in remmina_pref')
				else:
					password = ''
					self.statusBar.showMessage('Unable to find remmina.pref')

			# creating remmina files with permissions 400 is currently useless as remmina re-creates the file with 664 on exit with updated settings
			# protection is done by limiting access to our config dir
			if(os.path.isfile(self.cfgPathRemmina)):
				os.unlink(self.cfgPathRemmina)

			if(protocol == 'RDP'):
				# default config
				remminaConfig = ('[remmina]\n'+
					'name=$$host$$\n'+
					'server=$$host$$\n'+
					'username=$$username$$\n'+
					'password=$$password$$\n'
					'protocol=RDP\n'+
					'scale=2\n'+
					'window_width=1092\n'+
					'window_height=720\n'+
					'colordepth=0\n'+
					'sound=off\n')
				# use custom RDP config if provided
				cfgPathRemminaTemplate = self.cfgDir+'/rdp.remmina.template'
				if(os.path.isfile(cfgPathRemminaTemplate)):
					with open(cfgPathRemminaTemplate, 'r') as f:
						remminaConfig = f.read()
				# write temp remmina config
				with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						remminaConfig
							.replace('$$host$$', self.txtSearchComputer.text())
							.replace('$$username$$', self.cfgConnectUsername)
							.replace('$$password$$', password)
					)
					f.close()

			elif(protocol == 'SSH'):
				# default config
				remminaConfig = ('[remmina]\n'+
					'name=$$host$$\n'+
					'server=$$host$$\n'+
					'username=$$username$$\n'+
					'password=$$password$$\n'
					'protocol=SSH\n')
				# use custom SSH config if provided
				cfgPathRemminaTemplate = self.cfgDir+'/ssh.remmina.template'
				if(os.path.isfile(cfgPathRemminaTemplate)):
					with open(cfgPathRemminaTemplate, 'r') as f:
						remminaConfig = f.read()
				# write temp remmina config
				with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						remminaConfig
							.replace('$$host$$', self.txtSearchComputer.text())
							.replace('$$username$$', self.cfgConnectUsername)
							.replace('$$password$$', password)
					)
					f.close()

			time.sleep(0.2)
			subprocess.Popen(['remmina', '-c', self.cfgPathRemmina], env=self.prepareEnvironment())
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			print(traceback.format_exc())

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
			# clear text boxes
			for title, attribute in self.GetAttributesAsDict().items():
				textBox = self.refLdapAttributesTextBoxes[str(title)]
				self.updateTextboxText(textBox, '')
				textBox.setToolTip('')

			# start LDAP search
			self.connection.search(
				search_base = self.createLdapBase(self.connection),
				search_filter = self.cfgLdapQuery.replace('%1', computerName),
				attributes = ['cn']
			)
			for entry in self.connection.entries:
				self.statusBar.showMessage('Found: '+entry.entry_dn+' ('+self.GetConnectionString()+')')
				self.currentComputerName = str(entry['cn'])
				self.setWindowTitle(self.currentComputerName+' - '+__title__)
				self.tmpDn = entry.entry_dn
				self.queryAttributes()
				return

			# no result found
			self.statusBar.showMessage('No Result For: '+computerName+' ('+self.GetConnectionString()+')')
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
		dlg.exec()

	def queryAttributes(self):
		if(not self.reconnectForAttributeQuery()):
			self.btnSetExpirationTime.setEnabled(False)
			self.btnSearchComputer.setEnabled(True)
			return

		# start LDAP search
		self.connection.search(
			search_base = self.tmpDn,
			search_filter = '(objectClass=*)',
			attributes = ldap3.ALL_ATTRIBUTES
		)
		# display result
		for entry in self.connection.entries:
			# we are looking at the main computer object
			if(entry.entry_dn == self.tmpDn):
				self.btnSetExpirationTime.setEnabled(True)
				self.btnSearchComputer.setEnabled(True)

				# evaluate attributes of interest
				for title, attribute in self.GetAttributesAsDict().items():
					if(attribute[:4] == 'sub:'): continue
					textBox = self.refLdapAttributesTextBoxes[str(title)]
					value = None
					if(isinstance(attribute, list)):
						for _attribute in attribute:
							# use first non-empty attribute
							if(str(_attribute) in entry and entry[str(_attribute)]):
								value = entry[str(_attribute)]
								attribute = str(_attribute)
								break
					elif(str(attribute) in entry):
						value = entry[str(attribute)]

					# handle non-existing attributes
					if(value == None):
						pass

					# if this is the password attribute -> try to parse Native LAPS format
					elif(len(value) > 0 and
						(str(attribute) == self.cfgLdapAttributePassword or (isinstance(self.cfgLdapAttributePassword, list) and str(attribute) in self.cfgLdapAttributePassword))
					):
						password, username, timestamp = self.parseLapsValue(value.values[0])
						self.updateTextboxText(textBox, str(password))
						if(username and password):
							self.cfgConnectUsername = username
							textBox.setToolTip(username+', '+timestamp)

					# if this is the encrypted password history attribute -> try to parse Native LAPS format
					elif(len(value) > 0 and
						(str(attribute) == self.cfgLdapAttributePasswordHistory or (isinstance(self.cfgLdapAttributePasswordHistory, list) and str(attribute) in self.cfgLdapAttributePasswordHistory))
					):
						lines = []
						for _value in value.values:
							password, username, timestamp = self.parseLapsValue(_value)
							if(not username or not password):
								lines.append(str(password))
							else:
								lines.append(password+'  '+username+'  '+timestamp)
						self.updateTextboxText(textBox, "\n".join(lines))

					# if this is the expiry date attribute -> format date
					elif(str(attribute) == self.cfgLdapAttributePasswordExpiry or (isinstance(self.cfgLdapAttributePasswordExpiry, list) and str(attribute) in self.cfgLdapAttributePasswordExpiry)):
						try:
							self.updateTextboxText(textBox, str(filetime_to_dt( int(str(value)) )) )
						except Exception as e:
							print(str(e))
							self.updateTextboxText(textBox, str(value))

					# display raw value
					else:
						self.updateTextboxText(textBox, str(value))

			# we are looking at a sub-item of the computer object, e.g. a BitLocker recovery key
			else:
				for title, attribute in self.GetAttributesAsDict().items():
					textBox = self.refLdapAttributesTextBoxes[str(title)]
					if(attribute[:4] != 'sub:'): continue
					subattribute = str(attribute[4:])
					if(subattribute in entry):
						self.updateTextboxText(textBox, str(entry[subattribute]))

	def updateTextboxText(self, textBox, text):
		if(isinstance(textBox, QtWidgets.QPlainTextEdit)):
			textBox.setPlainText(text)
		else:
			textBox.setText(text)

	dpapiCache = dpapi_ng.KeyCache()
	def decryptPassword(self, blob):
		lastDecryptionError = ''
		for server in self.server.servers:
			try:
				kerberos_auth = (self.cfgUsername=='' or self.cfgPassword=='')
				decrypted = dpapi_ng.ncrypt_unprotect_secret(
					blob, server = server.host,
					username = None if kerberos_auth else self.cfgUsername,
					password = None if kerberos_auth else self.cfgPassword,
					cache = self.dpapiCache
				)
				return decrypted.decode('utf-8').replace("\x00", "")
			except Exception as e:
				if(lastDecryptionError != str(e)):
					self.showInfoDialog('Decryption Error', str(e), icon=QtWidgets.QMessageBox.Icons.Critical)
					lastDecryptionError = str(e)

	def parseLapsValue(self, ldapValue):
		try:
			# if type is bytes -> try to decrypt
			if(type(ldapValue) is bytes):
				decryptedValue = self.decryptPassword(ldapValue[16:])
				if(decryptedValue): ldapValue = decryptedValue

			# parse Native LAPS JSON
			jsonDict = json.loads(ldapValue)
			if(not 'n' in jsonDict or not 'p' in jsonDict or not 't' in jsonDict):
				raise Exception('Invalid LAPS JSON')
			return jsonDict['p'], jsonDict['n'], str(filetime_to_dt( int(jsonDict['t'], 16) ))

		except Exception as e:
			# directly use LDAP value as password (Legacy LAPS)
			return ldapValue, None, None

	def checkCredentialsAndConnect(self):
		# ask for server address and domain name if not already set via config file
		if(self.cfgDomain == None):
			item, ok = QtWidgets.QInputDialog.getText(self, '♕ Domain', 'Please enter your Domain name (e.g. example.com, leave empty to try auto discovery).')
			if ok and item != None:
				self.cfgDomain = item
				self.server = None
			else: return False
		if(len(self.cfgServer) == 0):
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
			if(len(self.cfgServer) == 0):
				item, ok = QtWidgets.QInputDialog.getText(self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
				if ok and item:
					self.cfgServer.append({
						'address': item,
						'port': 389,
						'ssl': False
					})
					self.server = None
		self.SaveSettings()

		# disable STARTTLS if SSL is used (otherwise, ldap3 will try to do STARTTLS on port 636)
		if(len(self.cfgServer) > 0 and self.cfgServer[0]['ssl'] == True):
			self.cfgUseStartTls = False

		# establish server connection
		if(self.server == None):
			try:
				serverArray = []
				for server in self.cfgServer:
					port = server['port']
					if('gc-port' in server):
						port = server['gc-port']
						self.gcModeOn = True
					serverArray.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], tls=self.tlsSettings, get_info=ldap3.ALL))
				self.server = ldap3.ServerPool(serverArray, ldap3.FIRST, active=2, exhaust=True)
			except Exception as e:
				self.showInfoDialog('Error connecting to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
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
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				self.statusBar.showMessage(str(e))
				return False

		# ask for username and password for SIMPLE bind
		if(self.cfgUsername == '' or self.cfgPassword == ''):
			loginWindow = LapsLoginWindow(
				username = proposeUsername(self.cfgDomain) if self.cfgUsername == '' else self.cfgUsername,
				server = str(compileServerUris(self.cfgServer))
			)
			if(loginWindow.exec() != QtWidgets.QDialog.DialogCode.Accepted):
				return False
			self.connection = None
			self.cfgUsername = loginWindow.txtUsername.text()
			self.cfgPassword = loginWindow.txtPassword.text()
			self.SaveSettings()

		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(
				self.server,
				user=self.cfgUsername,
				password=self.cfgPassword,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
			)
			if(self.cfgUseStartTls): self.connection.start_tls()
		except Exception as e:
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				self.statusBar.showMessage(str(e))
				return False
			self.cfgPassword = ''
			self.showInfoDialog('Error binding to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
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
				user=self.cfgUsername,
				password=self.cfgPassword,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfgUseStartTls else True)
			)
			if(self.cfgUseStartTls): self.connection.start_tls()
			return True
		except Exception as e:
			self.showInfoDialog('Error binding to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
			return False

	def createLdapBase(self, conn):
		if self.cfgDomain:
			# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
			search_base = ''
			base = self.cfgDomain.split('.')
			for b in base:
				search_base += 'DC=' + b + ','
			return search_base[:-1]
		elif conn.server.info and 'defaultNamingContext' in conn.server.info.raw:
			return conn.server.info.raw['defaultNamingContext'][0].decode('utf-8')
		else:
			raise Exception('Could not create LDAP search base: reading defaultNamingContext from LDAP directory failed and no domain given.')

	def GetConnectionString(self):
		return str(self.connection.server.host)+' '+str(self.connection.user)

	def LoadSettings(self):
		if(not path.isdir(self.cfgDir)):
			makedirs(self.cfgDir, exist_ok=True)
		# protect temporary .remmina file by limiting access to our config folder
		if(self.PLATFORM == 'linux'): os.chmod(self.cfgDir, 0o700)

		dctPresetSettings = {}
		dctUserSettings = {}
		cfgJson = {}

		try:
			if(path.isfile(self.cfgPath)):
				with open(self.cfgPath) as f:
					dctUserSettings = json.load(f)
					cfgJson = dctUserSettings
			if(path.isfile(self.cfgPresetPath)):
				with open(self.cfgPresetPath) as f:
					dctPresetSettings = json.load(f)
					# use preset config if version is higher or user settings are empty
					if(dctPresetSettings.get('version', 0) > dctUserSettings.get('version', 0)
					or dctUserSettings == {}):
						cfgJson = dctPresetSettings

			self.cfgVersion = cfgJson.get('version', self.cfgVersion)
			self.cfgUseKerberos = cfgJson.get('use-kerberos', self.cfgUseKerberos)
			self.cfgUseStartTls = cfgJson.get('use-starttls', self.cfgUseStartTls)
			self.cfgServer = cfgJson.get('server', self.cfgServer)
			self.cfgDomain = cfgJson.get('domain', self.cfgDomain)
			self.cfgLdapQuery = cfgJson.get('ldap-query', self.cfgLdapQuery)
			self.cfgUsername = cfgJson.get('username', self.cfgUsername)
			self.cfgLdapAttributePassword = cfgJson.get('ldap-attribute-password', self.cfgLdapAttributePassword)
			self.cfgLdapAttributePasswordExpiry = cfgJson.get('ldap-attribute-password-expiry', self.cfgLdapAttributePasswordExpiry)
			self.cfgLdapAttributePasswordHistory = cfgJson.get('ldap-attribute-password-history', self.cfgLdapAttributePasswordHistory)
			tmpLdapAttributes = cfgJson.get('ldap-attributes', self.cfgLdapAttributes)
			self.cfgConnectUsername = str(cfgJson.get('connect-username', self.cfgConnectUsername))
			self.cfgUseAutotypeEnter = cfgJson.get('use-autotype-enter', self.cfgUseAutotypeEnter)
			if(isinstance(tmpLdapAttributes, list) or isinstance(tmpLdapAttributes, dict)):
				self.cfgLdapAttributes = tmpLdapAttributes
		except Exception as e:
			self.showInfoDialog('Error loading settings file', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)

	def SaveSettings(self):
		try:
			# do not save auto-discovered servers to config - should be queried every time
			saveServers = []
			for server in self.cfgServer:
				if not server.get('auto-discovered', False):
					saveServers.append(server)

			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'version': self.cfgVersion,
					'use-kerberos': self.cfgUseKerberos,
					'use-starttls': self.cfgUseStartTls,
					'server': saveServers,
					'domain': self.cfgDomain,
					'ldap-query': self.cfgLdapQuery,
					'username': self.cfgUsername,
					'ldap-attribute-password': self.cfgLdapAttributePassword,
					'ldap-attribute-password-expiry': self.cfgLdapAttributePasswordExpiry,
					'ldap-attribute-password-history': self.cfgLdapAttributePasswordHistory,
					'ldap-attributes': self.cfgLdapAttributes,
					'connect-username': self.cfgConnectUsername,
					'use-autotype-enter': self.cfgUseAutotypeEnter,
				}, json_file, indent=4)
		except Exception as e:
			self.showInfoDialog('Error saving settings file', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)

	def showInfoDialog(self, title, text, additionalText='', icon=QtWidgets.QMessageBox.Icon.Information):
		print('Dialog:', title, ':', text, ':', additionalText, ':', icon)
		msg = QtWidgets.QMessageBox()
		msg.setIcon(icon)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additionalText)
		msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
		retval = msg.exec()

def main():
	# as long as we want to support Debian 11 and Ubuntu 22.04,
	# we need to fall back to X11 Qt Platform Plugin because those
	# distros have a too old libwayland on board, causing a crash
	# "undefined symbol: wl_proxy_marshal_flags"
	if(sys.platform == 'linux'):
		os.environ.setdefault('QT_QPA_PLATFORM', 'xcb')

	app = QtWidgets.QApplication(sys.argv)
	window = LapsMainWindow()
	window.show()
	sys.exit(app.exec())

if __name__ == '__main__':
	main()
