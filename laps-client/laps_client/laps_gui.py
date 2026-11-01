#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .__init__ import __title__, __version__, __website__, __author__, __copyright__
from .__init__ import propose_username, compile_server_uris
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
		self.init_ui()

	def init_ui(self):
		self.button_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok)
		self.button_box.accepted.connect(self.accept)

		self.layout = QtWidgets.QVBoxLayout(self)

		label_app_name = QtWidgets.QLabel(self)
		label_app_name.setText(__title__ + ' GUI Client' + ' v' + __version__)
		label_app_name.setStyleSheet('font-weight:bold')
		label_app_name.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(label_app_name)

		label_copyright = QtWidgets.QLabel(self)
		label_copyright.setText(
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
		label_copyright.setOpenExternalLinks(True)
		label_copyright.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(label_copyright)

		label_description = QtWidgets.QLabel(self)
		label_description.setText(
			'LAPS4LINUX client allows you to query local administrator passwords for LAPS runner managed workstations in your domain from your LDAP (Active Directory) server.'
			'\n\n'
			'The LAPS runner periodically sets a new administrator password and saves it into the LDAP directory.'
			'\n\n'
			'LAPS was originally developed by Microsoft, this is an unofficial Linux/Unix implementation with some enhancements (e.g. the CLI/GUI client can display additional attributes).'
		)
		label_description.setFixedWidth(450)
		label_description.setWordWrap(True)
		self.layout.addWidget(label_description)

		self.layout.addWidget(self.button_box)

		self.setLayout(self.layout)
		self.setWindowTitle('About')

class LapsLoginWindow(QtWidgets.QDialog):
	def __init__(self, server, username, *args, **kwargs):
		super(LapsLoginWindow, self).__init__(*args, **kwargs)

		# window layout
		self.button_box = QtWidgets.QDialogButtonBox(
			QtWidgets.QDialogButtonBox.StandardButton.Ok
			| QtWidgets.QDialogButtonBox.StandardButton.Cancel
		)
		self.button_box.accepted.connect(self.accept)
		self.button_box.rejected.connect(self.reject)

		self.layout = QtWidgets.QGridLayout(self)

		self.lbl_description = QtWidgets.QLabel('Please enter the credentials which should be used to connect to:\n'+server)
		self.layout.addWidget(self.lbl_description, 0, 0, 1, 2)

		self.lbl_username = QtWidgets.QLabel('Username')
		self.layout.addWidget(self.lbl_username, 1, 0)
		self.txt_username = QtWidgets.QLineEdit()
		self.txt_username.setText(username)
		self.layout.addWidget(self.txt_username, 1, 1, 1, 2)

		self.lbl_password = QtWidgets.QLabel('Password')
		self.layout.addWidget(self.lbl_password, 2, 0)
		self.txt_password = QtWidgets.QLineEdit()
		self.txt_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
		self.layout.addWidget(self.txt_password, 2, 1, 1, 2)

		self.layout.addWidget(self.button_box, 3, 1, 1, 2)
		self.setLayout(self.layout)

		# window properties
		self.setWindowTitle('LDAP Bind Credentials')
		self.resize(350, 150)
		#self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)

		if(self.txt_username.text() != ''):
			self.txt_password.setFocus()

class LapsBarcodeWindow(QtWidgets.QDialog):
	def __init__(self, title, value, img, *args, **kwargs):
		super(LapsBarcodeWindow, self).__init__(*args, **kwargs)
		self.title = title
		self.value = value
		self.img = img
		self.init_ui()

	def init_ui(self):
		parent_widget = self.parentWidget()

		# Menubar
		main_menu = QtWidgets.QMenuBar(self)
		file_menu = main_menu.addMenu('&File')
		save_action = QtGui.QAction('&Save image', self)
		save_action.setShortcut('F2')
		save_action.triggered.connect(self.on_click_save)
		file_menu.addAction(save_action)
		file_menu.addSeparator()
		close_action = QtGui.QAction('&Close', self)
		close_action.triggered.connect(self.on_click_close)
		file_menu.addAction(close_action)

		self.layout = QtWidgets.QVBoxLayout()
		self.layout.setContentsMargins(20, 50, 20, 20)

		if(self.img.mode == '1'):
			self.img = self.img.convert('RGBA')
		img_bytes = self.img.tobytes('raw', 'RGBA')
		label_image = QtWidgets.QLabel(self)
		c = QtGui.QCursor(QtCore.Qt.CursorShape.BlankCursor)
		label_image.setCursor(c)
		label_image.setPixmap(QtGui.QPixmap.fromImage(QtGui.QImage(img_bytes, self.img.size[0], self.img.size[1], QtGui.QImage.Format.Format_RGBA8888)))
		label_image.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		self.layout.addWidget(label_image)

		label_text = QtWidgets.QLabel(self)
		label_text.setText(self.value)
		label_text.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		label_text.setFont(parent_widget.text_box_font)
		self.layout.addWidget(label_text)

		self.setLayout(self.layout)
		self.setWindowTitle(self.title)

	def on_click_save(self):
		file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save image', self.title+'.png', 'PNG Files (*.png);;All Files (*.*)')
		if(file_name):
			self.img.save(file_name)

	def on_click_close(self):
		self.close()

class LapsCalendarWindow(QtWidgets.QDialog):
	def __init__(self, *args, **kwargs):
		super(LapsCalendarWindow, self).__init__(*args, **kwargs)
		self.init_ui()

	def init_ui(self):
		self.button_box = QtWidgets.QDialogButtonBox(
			QtWidgets.QDialogButtonBox.StandardButton.Ok
			| QtWidgets.QDialogButtonBox.StandardButton.Cancel
		)
		self.button_box.accepted.connect(self.on_click_accept)
		self.button_box.rejected.connect(self.on_click_reject)

		self.layout = QtWidgets.QVBoxLayout(self)

		self.cw_new_expiration_time = QtWidgets.QCalendarWidget()
		self.layout.addWidget(self.cw_new_expiration_time)

		self.layout.addWidget(self.button_box)

		self.setLayout(self.layout)
		self.setWindowTitle('Set New Expiration Date')

	def on_click_accept(self):
		parent_widget = self.parentWidget()

		# check if dn of target computer object is known
		if parent_widget.tmp_dn.strip() == '': return

		try:
			if isinstance(parent_widget.cfg_ldap_attribute_password_expiry, list) and len(parent_widget.cfg_ldap_attribute_password_expiry) > 0:
				attribute_expiration_date = parent_widget.cfg_ldap_attribute_password_expiry[0]
			else:
				attribute_expiration_date = str(parent_widget.cfg_ldap_attribute_password_expiry)

			# calc new time
			new_expiration_date = datetime.combine(self.cw_new_expiration_time.selectedDate().toPyDate(), datetime.min.time())
			new_expiration_date_time = dt_to_filetime(new_expiration_date)
			print('new expiration time: '+str(new_expiration_date_time))

			# start LDAP modify
			parent_widget.connection.modify(parent_widget.tmp_dn, { attribute_expiration_date: [(ldap3.MODIFY_REPLACE, [str(new_expiration_date_time)])] })
			if parent_widget.connection.result['result'] == 0:
				parent_widget.show_info_dialog('Success',
					'Expiration date successfully changed to '+str(new_expiration_date)+'.',
					parent_widget.tmp_dn+' ('+parent_widget.get_connection_string()+')'
				)
				# update values in main window
				parent_widget.on_click_search(None)
				self.close()
			else:
				parent_widget.show_info_dialog('Error',
					'Unable to change expiration date to '+str(new_expiration_date_time)+'.'
					+'\n\n'+str(parent_widget.connection.result['message']), parent_widget.tmp_dn+' ('+parent_widget.get_connection_string()+')',
					icon=QtWidgets.QMessageBox.Icon.Critical
				)

		except Exception as e:
			# display error
			parent_widget.show_info_dialog('Error setting new expiration date', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
			# reset connection
			parent_widget.server = None
			parent_widget.connection = None

	def on_click_reject(self):
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

	gc_mode_on            = False
	server                = None
	connection            = None
	tmp_dn                = ''
	current_computer_name = ''

	cfg_preset_dir_windows = path.dirname(sys.executable) if getattr(sys, 'frozen', False) else sys.path[0]
	cfg_preset_dir_unix    = '/etc'
	cfg_preset_file        = 'laps-client.json'
	cfg_preset_path        = (cfg_preset_dir_windows if PLATFORM=='win32' else cfg_preset_dir_unix)+'/'+cfg_preset_file

	cfg_dir             = str(Path.home())+'/.config/laps-client'
	cfg_path            = cfg_dir+'/settings.json'
	cfg_path_remmina    = cfg_dir+'/laps.remmina'
	cfg_version         = 0
	cfg_use_kerberos    = True
	cfg_use_start_tls   = True
	cfg_server          = []
	cfg_domain          = None
	cfg_ldap_query      = '(&(objectClass=computer)(cn=%1))'
	cfg_username        = ''
	cfg_password        = ''
	cfg_ldap_attributes = {
		'Operating System':               'operatingSystem',
		'Administrator Password':         ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd'],
		'Password Expiration Date':       ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'],
		'Administrator Password History': 'msLAPS-EncryptedPasswordHistory'
	}
	cfg_ldap_attribute_password         = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd']
	cfg_ldap_attribute_password_expiry  = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
	cfg_ldap_attribute_password_history = 'msLAPS-EncryptedPasswordHistory'
	cfg_ca_certs_file                   = None
	cfg_tls_validate                    = ssl.CERT_REQUIRED
	cfg_connect_username                = 'administrator'
	cfg_use_autotype_enter              = False
	ref_ldap_attributes_text_boxes      = {}


	def __init__(self):
		super(LapsMainWindow, self).__init__()
		self.load_settings()
		self.init_ui()

	def init_ui(self):
		# Icon Selection
		if(getattr(sys, 'frozen', False)):
			# included via pyinstaller (Windows & macOS)
			self.PRODUCT_ICON_PATH = sys._MEIPASS
		self.icon_path = path.join(self.PRODUCT_ICON_PATH, self.PRODUCT_ICON)
		if(path.exists(self.icon_path)):
			self.icon = QtGui.QIcon(self.icon_path)
			self.setWindowIcon(self.icon)

		# Menubar
		main_menu = self.menuBar()

		# File Menu
		file_menu = main_menu.addMenu('&File')

		search_action = QtGui.QAction('&Search', self)
		search_action.setShortcut('F2')
		search_action.triggered.connect(self.on_click_search)
		file_menu.addAction(search_action)
		if(self.cfg_ldap_attribute_password_expiry):
			set_expiration_date_action = QtGui.QAction('Set &Expiration', self)
			set_expiration_date_action.setShortcut('F3')
			set_expiration_date_action.triggered.connect(self.on_click_set_expiry)
			file_menu.addAction(set_expiration_date_action)
		file_menu.addSeparator()
		kerberos_action = QtGui.QAction('&Kerberos Authentication', self)
		kerberos_action.setShortcut('Ctrl+K')
		kerberos_action.setCheckable(True)
		kerberos_action.setChecked(self.cfg_use_kerberos)
		kerberos_action.triggered.connect(self.on_click_kerberos)
		file_menu.addAction(kerberos_action)
		file_menu.addSeparator()
		quit_action = QtGui.QAction('&Quit', self)
		quit_action.setShortcut('Ctrl+Q')
		quit_action.triggered.connect(self.on_quit)
		file_menu.addAction(quit_action)

		# Connection Menu
		connect_menu = main_menu.addMenu('&Connect')

		rdp_action = QtGui.QAction('&RDP', self)
		rdp_action.setShortcut('F5')
		rdp_action.triggered.connect(lambda: self.remote_connection('RDP'))
		connect_menu.addAction(rdp_action)
		ssh_action = QtGui.QAction('&SSH', self)
		ssh_action.setShortcut('F6')
		ssh_action.triggered.connect(lambda: self.remote_connection('SSH'))
		connect_menu.addAction(ssh_action)
		connect_menu.addSeparator()
		autotype_code_action = QtGui.QAction('&Autotype QR code', self)
		autotype_code_action.setShortcut('F7')
		autotype_code_action.triggered.connect(self.on_click_autotype_code)
		connect_menu.addAction(autotype_code_action)
		autotype_separator_action = QtGui.QAction('Enter instead of Tab', self)
		autotype_separator_action.setCheckable(True)
		autotype_separator_action.setChecked(self.cfg_use_autotype_enter)
		autotype_separator_action.triggered.connect(self.on_click_autotype_enter)
		connect_menu.addAction(autotype_separator_action)

		# Help Menu
		help_menu = main_menu.addMenu('&Help')

		about_action = QtGui.QAction('&About', self)
		about_action.setShortcut('F1')
		about_action.triggered.connect(self.on_open_about_dialog)
		help_menu.addAction(about_action)

		# Statusbar
		self.status_bar = self.statusBar()

		# Window Content
		grid = QtWidgets.QGridLayout()
		grid_line = 0

		self.lbl_search_computer = QtWidgets.QLabel('Computer Name')
		grid.addWidget(self.lbl_search_computer, grid_line, 0)
		grid_line += 1
		self.txt_search_computer = QtWidgets.QLineEdit()
		self.txt_search_computer.returnPressed.connect(self.on_return_search)
		self.txt_search_computer.contextMenuEvent = partial(self.on_context_menu, self.txt_search_computer)
		grid.addWidget(self.txt_search_computer, grid_line, 0)
		self.btn_search_computer = QtWidgets.QPushButton('Search')
		self.btn_search_computer.clicked.connect(self.on_click_search)
		grid.addWidget(self.btn_search_computer, grid_line, 1)
		grid_line += 1

		self.btn_set_expiration_time = QtWidgets.QPushButton('Set')
		self.btn_set_expiration_time.setEnabled(False)
		self.btn_set_expiration_time.clicked.connect(self.on_click_set_expiry)

		for title, attribute in self.get_attributes_as_dict().items():
			# create label
			lbl_additional_attribute = QtWidgets.QLabel(str(title))
			grid.addWidget(lbl_additional_attribute, grid_line, 0)
			grid_line += 1

			# instantiate single or multiline textbox
			if(attribute == self.cfg_ldap_attribute_password_history
			or (isinstance(self.cfg_ldap_attribute_password_history, list) and attribute in self.cfg_ldap_attribute_password_history)):
				txt_additional_attribute = LapsPlainTextEdit()
				txt_additional_attribute.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
			else:
				txt_additional_attribute = QtWidgets.QLineEdit()
			txt_additional_attribute.setReadOnly(True)
			txt_additional_attribute.contextMenuEvent = partial(self.on_context_menu, txt_additional_attribute)

			# set easy readable font
			if(self.PLATFORM == 'win32'):
				self.text_box_font = QtGui.QFont('Consolas', 14)
				self.text_box_font.setBold(True)
			else:
				self.text_box_font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
				self.text_box_font.setPointSize(18 if self.PLATFORM=='darwin' else 14)
			txt_additional_attribute.setFont(self.text_box_font)

			# add textbox to layout
			grid.addWidget(txt_additional_attribute, grid_line, 0)
			self.ref_ldap_attributes_text_boxes[str(title)] = txt_additional_attribute

			# create copy/set button
			if(attribute == self.cfg_ldap_attribute_password_expiry
			or (isinstance(self.cfg_ldap_attribute_password_expiry, list) and attribute in self.cfg_ldap_attribute_password_expiry)):
				grid.addWidget(self.btn_set_expiration_time, grid_line, 1)
			else:
				btn_copy = QtWidgets.QPushButton('Copy')
				btn_copy.clicked.connect(partial(self.on_click_copy, txt_additional_attribute))
				grid.addWidget(btn_copy, grid_line, 1)
			grid_line += 1

		widget = QtWidgets.QWidget(self)
		widget.setLayout(grid)
		self.setCentralWidget(widget)

		# Window Settings
		self.setMinimumSize(480, 300)
		self.setWindowTitle(__title__)
		self.status_bar.showMessage('Settings file: '+self.cfg_path)

		# Handle Parameter - Automatic Search
		url_to_handle = None
		for arg in sys.argv:
			if(arg.startswith(self.PROTOCOL_SCHEME)):
				url_to_handle = arg
		if(url_to_handle != None):
			print('Handle '+url_to_handle)
			protocol_payload = unquote(url_to_handle).replace(self.PROTOCOL_SCHEME, '').strip(' /')
			self.txt_search_computer.setText(protocol_payload)
			self.on_click_search(None)

	def get_attributes_as_dict(self):
		final_dict = {}
		if(isinstance(self.cfg_ldap_attributes, list)):
			for attribute in self.cfg_ldap_attributes:
				final_dict[attribute] = attribute
		elif(isinstance(self.cfg_ldap_attributes, dict)):
			for title, attribute in self.cfg_ldap_attributes.items():
				final_dict[str(title)] = attribute
		return final_dict

	def on_quit(self, e):
		sys.exit()

	def on_context_menu(self, line_edit, e):
		menu = line_edit.createStandardContextMenu()
		qr_action = QtGui.QAction('Show as QR code', self)
		qr_action.triggered.connect(lambda: self.on_click_show_as_code(line_edit, 'qr'))
		menu.addAction(qr_action)
		barcode_action = QtGui.QAction('Show as barcode', self)
		barcode_action.triggered.connect(lambda: self.on_click_show_as_code(line_edit, 'barcode'))
		menu.addAction(barcode_action)
		menu.exec(e.globalPos())

	def on_click_show_as_code(self, line_edit, code):
		if(isinstance(line_edit, QtWidgets.QPlainTextEdit)):
			text = line_edit.toPlainText()
		else:
			text = line_edit.text()
		if(not text): return
		self.show_code(text, code)

	def on_click_copy(self, line_edit, e):
		if(isinstance(line_edit, QtWidgets.QPlainTextEdit)):
			text = line_edit.toPlainText()
		else:
			text = line_edit.text()
		cb = QtWidgets.QApplication.clipboard()
		cb.clear(mode=QtGui.QClipboard.Mode.Clipboard)
		cb.setText(text, mode=QtGui.QClipboard.Mode.Clipboard)

	def on_click_kerberos(self, e):
		self.cfg_use_kerberos = not self.cfg_use_kerberos
		self.save_settings()

	def on_click_autotype_enter(self, e):
		self.cfg_use_autotype_enter = not self.cfg_use_autotype_enter
		self.save_settings()

	def on_open_about_dialog(self, e):
		dlg = LapsAboutWindow(self)
		dlg.exec()

	def on_return_search(self):
		self.on_click_search(None)

	def on_click_autotype_code(self):
		separator = "\t"
		if(self.cfg_use_autotype_enter):
			# for Linux login screens (lightdm etc.)
			separator = "\n"
		text = self.cfg_connect_username + separator + self.get_current_password()
		self.show_code(text, 'qr')

	def show_code(self, text, code):
		if(code == 'qr'):
			import qrcode
			img = qrcode.make(text).get_image()
		else:
			import barcode
			barcode.base.Barcode.default_writer_options['write_text'] = False
			img = barcode.Code128(text, writer=barcode.writer.ImageWriter()).render()
		if(img):
			dlg = LapsBarcodeWindow(self.current_computer_name, text, img, self)
			dlg.show()

	def version_tuple(self, v):
		return tuple(map(int, (v.split('.'))))

	def prepare_environment(self):
		# restore library search path for subprocess (modified by PyInstaller)
		# see https://pyinstaller.org/en/v6.9.0/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application
		sub_env = os.environ.copy()
		if('LD_LIBRARY_PATH_ORIG' in sub_env):
			sub_env['LD_LIBRARY_PATH'] = sub_env['LD_LIBRARY_PATH_ORIG']
		elif('LD_LIBRARY_PATH' in sub_env):
			del sub_env['LD_LIBRARY_PATH']
		return sub_env

	def get_current_password(self):
		password = ''
		for title, attribute in self.get_attributes_as_dict().items():
			if((isinstance(self.cfg_ldap_attribute_password, str) and isinstance(attribute, str) and attribute.upper() == self.cfg_ldap_attribute_password.upper())
			or attribute == self.cfg_ldap_attribute_password):
				if(title in self.ref_ldap_attributes_text_boxes):
					password = self.ref_ldap_attributes_text_boxes[title].text()
		return password

	def remote_connection(self, protocol):
		if(self.txt_search_computer.text().strip() == ''):
			return

		# only available on linux as there is no reasonable way to open remote connections with password on other OSes
		if(self.PLATFORM != 'linux'):
			self.show_info_dialog('Nope.', 'Only available on non-shitty operating systems.', icon=QtWidgets.QMessageBox.Icon.Warning)
			return

		try:
			import subprocess, time
			from shutil import which

			# check remmina existence and version
			if(which('remmina') is None): raise Exception('Remmina is not installed')
			new_remmina = False
			res = subprocess.run('remmina --version | grep org.remmina.Remmina | cut -d- -f2 | cut -d"(" -f1 | xargs', shell=True, env=self.prepare_environment(), stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
			if(self.version_tuple(res.stdout.decode('utf-8')) >= self.version_tuple('1.4.25')):
				new_remmina = True

			# get current admin password
			password = self.get_current_password()

			# passwords must be encrypted in old remmina connection files using the secret found in remmina.pref
			if(not new_remmina):
				import base64, configparser
				from Cryptodome.Cipher import DES3

				remmina_pref_path = str(Path.home())+'/.remmina/remmina.pref' # older remmina versions
				if(not os.path.exists(remmina_pref_path)): remmina_pref_path = str(Path.home())+'/.config/remmina/remmina.pref' # newer remmina versions
				if(os.path.exists(remmina_pref_path)):
					config = configparser.ConfigParser()
					config.read(remmina_pref_path)
					if(config.has_section('remmina_pref') and 'secret' in config['remmina_pref'] and config['remmina_pref']['secret'].strip() != ''):
						secret = base64.b64decode(config['remmina_pref']['secret'])
						padding = chr(0) * (8 - len(password) % 8)
						password = base64.b64encode( DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).encrypt((password+padding).encode("utf8")) ).decode('utf-8')
					else:
						password = ''
						self.status_bar.showMessage('Unable to find secret in remmina_pref')
				else:
					password = ''
					self.status_bar.showMessage('Unable to find remmina.pref')

			# creating remmina files with permissions 400 is currently useless as remmina re-creates the file with 664 on exit with updated settings
			# protection is done by limiting access to our config dir
			if(os.path.isfile(self.cfg_path_remmina)):
				os.unlink(self.cfg_path_remmina)

			if(protocol == 'RDP'):
				# default config
				remmina_config = ('[remmina]\n'+
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
				cfg_path_remmina_template = self.cfg_dir+'/rdp.remmina.template'
				if(os.path.isfile(cfg_path_remmina_template)):
					with open(cfg_path_remmina_template, 'r') as f:
						remmina_config = f.read()
				# write temp remmina config
				with open(os.open(self.cfg_path_remmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						remmina_config
							.replace('$$host$$', self.txt_search_computer.text())
							.replace('$$username$$', self.cfg_connect_username)
							.replace('$$password$$', password)
					)

			elif(protocol == 'SSH'):
				# default config
				remmina_config = ('[remmina]\n'+
					'name=$$host$$\n'+
					'server=$$host$$\n'+
					'username=$$username$$\n'+
					'password=$$password$$\n'
					'protocol=SSH\n')
				# use custom SSH config if provided
				cfg_path_remmina_template = self.cfg_dir+'/ssh.remmina.template'
				if(os.path.isfile(cfg_path_remmina_template)):
					with open(cfg_path_remmina_template, 'r') as f:
						remmina_config = f.read()
				# write temp remmina config
				with open(os.open(self.cfg_path_remmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
					f.write(
						remmina_config
							.replace('$$host$$', self.txt_search_computer.text())
							.replace('$$username$$', self.cfg_connect_username)
							.replace('$$password$$', password)
					)

			time.sleep(0.2)
			subprocess.Popen(['remmina', '-c', self.cfg_path_remmina], env=self.prepare_environment())
		except Exception as e:
			# display error
			self.status_bar.showMessage(str(e))
			print(traceback.format_exc())

	def on_click_search(self, e):
		# check and escape input
		computer_name = self.txt_search_computer.text()
		if computer_name.strip() == '': return
		computer_name = ldap3.utils.conv.escape_filter_chars(computer_name)

		# ask for credentials
		self.btn_search_computer.setEnabled(False)
		if not self.check_credentials_and_connect():
			self.btn_search_computer.setEnabled(True)
			return

		try:
			# clear text boxes
			for title, attribute in self.get_attributes_as_dict().items():
				text_box = self.ref_ldap_attributes_text_boxes[str(title)]
				self.update_textbox_text(text_box, '')
				text_box.setToolTip('')

			# start LDAP search
			self.connection.search(
				search_base = self.create_ldap_base(self.connection),
				search_filter = self.cfg_ldap_query.replace('%1', computer_name),
				attributes = ['cn']
			)
			for entry in self.connection.entries:
				self.status_bar.showMessage('Found: '+entry.entry_dn+' ('+self.get_connection_string()+')')
				self.current_computer_name = str(entry['cn'])
				self.setWindowTitle(self.current_computer_name+' - '+__title__)
				self.tmp_dn = entry.entry_dn
				self.query_attributes()
				return

			# no result found
			self.status_bar.showMessage('No Result For: '+computer_name+' ('+self.get_connection_string()+')')
		except Exception as e:
			# display error
			self.status_bar.showMessage(str(e))
			print(str(e))
			# reset connection
			self.server = None
			self.connection = None

		self.tmp_dn = ''
		self.btn_set_expiration_time.setEnabled(False)
		self.btn_search_computer.setEnabled(True)

	def on_click_set_expiry(self, e):
		# check if dn of target computer object is known
		if self.tmp_dn.strip() == '': return

		dlg = LapsCalendarWindow(self)
		dlg.exec()

	def query_attributes(self):
		if(not self.reconnect_for_attribute_query()):
			self.btn_set_expiration_time.setEnabled(False)
			self.btn_search_computer.setEnabled(True)
			return

		# start LDAP search
		self.connection.search(
			search_base = self.tmp_dn,
			search_filter = '(objectClass=*)',
			attributes = ldap3.ALL_ATTRIBUTES
		)
		# display result
		for entry in self.connection.entries:
			# we are looking at the main computer object
			if(entry.entry_dn == self.tmp_dn):
				self.btn_set_expiration_time.setEnabled(True)
				self.btn_search_computer.setEnabled(True)

				# evaluate attributes of interest
				for title, attribute in self.get_attributes_as_dict().items():
					if(attribute[:4] == 'sub:'): continue
					text_box = self.ref_ldap_attributes_text_boxes[str(title)]
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
						(str(attribute) == self.cfg_ldap_attribute_password or (isinstance(self.cfg_ldap_attribute_password, list) and str(attribute) in self.cfg_ldap_attribute_password))
					):
						password, username, timestamp = self.parse_laps_value(value.values[0])
						self.update_textbox_text(text_box, str(password))
						if(username and password):
							self.cfg_connect_username = username
							text_box.setToolTip(username+', '+timestamp)

					# if this is the encrypted password history attribute -> try to parse Native LAPS format
					elif(len(value) > 0 and
						(str(attribute) == self.cfg_ldap_attribute_password_history or (isinstance(self.cfg_ldap_attribute_password_history, list) and str(attribute) in self.cfg_ldap_attribute_password_history))
					):
						lines = []
						for _value in value.values:
							password, username, timestamp = self.parse_laps_value(_value)
							if(not username or not password):
								lines.append(str(password))
							else:
								lines.append(password+'  '+username+'  '+timestamp)
						self.update_textbox_text(text_box, "\n".join(lines))

					# if this is the expiry date attribute -> format date
					elif(str(attribute) == self.cfg_ldap_attribute_password_expiry or (isinstance(self.cfg_ldap_attribute_password_expiry, list) and str(attribute) in self.cfg_ldap_attribute_password_expiry)):
						try:
							self.update_textbox_text(text_box, str(filetime_to_dt( int(str(value)) )) )
						except Exception as e:
							print(str(e))
							self.update_textbox_text(text_box, str(value))

					# display raw value
					else:
						self.update_textbox_text(text_box, str(value))

			# we are looking at a sub-item of the computer object, e.g. a BitLocker recovery key
			else:
				for title, attribute in self.get_attributes_as_dict().items():
					text_box = self.ref_ldap_attributes_text_boxes[str(title)]
					if(attribute[:4] != 'sub:'): continue
					subattribute = str(attribute[4:])
					if(subattribute in entry):
						self.update_textbox_text(text_box, str(entry[subattribute]))

	def update_textbox_text(self, text_box, text):
		if(isinstance(text_box, QtWidgets.QPlainTextEdit)):
			text_box.setPlainText(text)
		else:
			text_box.setText(text)

	dpapi_cache = dpapi_ng.KeyCache()
	def decrypt_password(self, blob):
		last_decryption_error = ''
		for server in self.server.servers:
			try:
				kerberos_auth = (self.cfg_username=='' or self.cfg_password=='')
				decrypted = dpapi_ng.ncrypt_unprotect_secret(
					blob, server = server.host,
					username = None if kerberos_auth else self.cfg_username,
					password = None if kerberos_auth else self.cfg_password,
					cache = self.dpapi_cache
				)
				return decrypted.decode('utf-8').replace("\x00", "")
			except Exception as e:
				if(last_decryption_error != str(e)):
					self.show_info_dialog('Decryption Error', str(e), icon=QtWidgets.QMessageBox.Icons.Critical)
					last_decryption_error = str(e)

	def parse_laps_value(self, ldap_value):
		try:
			# if type is bytes -> try to decrypt
			if(type(ldap_value) is bytes):
				decrypted_value = self.decrypt_password(ldap_value[16:])
				if(decrypted_value): ldap_value = decrypted_value

			# parse Native LAPS JSON
			json_dict = json.loads(ldap_value)
			if(not 'n' in json_dict or not 'p' in json_dict or not 't' in json_dict):
				raise Exception('Invalid LAPS JSON')
			return json_dict['p'], json_dict['n'], str(filetime_to_dt( int(json_dict['t'], 16) ))

		except Exception as e:
			# directly use LDAP value as password (Legacy LAPS)
			return ldap_value, None, None

	def check_credentials_and_connect(self):
		# ask for server address and domain name if not already set via config file
		if(self.cfg_domain == None):
			item, ok = QtWidgets.QInputDialog.getText(self, '♕ Domain', 'Please enter your Domain name (e.g. example.com, leave empty to try auto discovery).')
			if ok and item != None:
				self.cfg_domain = item
				self.server = None
			else: return False
		if(len(self.cfg_server) == 0):
			# query domain controllers by dns lookup
			search_domain = '.'+self.cfg_domain if self.cfg_domain!='' else ''
			try:
				res = resolver.resolve(qname='_ldap._tcp'+search_domain, rdtype=rdatatype.SRV, lifetime=10, search=True)
				for srv in res.rrset:
					server_entry = {
						# strip the trailing . from the dns resolver for certificate verification reasons.
						'address': str(srv.target).rstrip('.'),
						'port': srv.port,
						'ssl': (srv.port == 636),
						'auto-discovered': True
					}
					print('DNS auto discovery found server: '+json.dumps(server_entry, indent=2))
					self.cfg_server.append(server_entry)
			except Exception as e: print('DNS auto discovery failed: '+str(e))
			# ask user to enter server names if auto discovery was not successful
			if(len(self.cfg_server) == 0):
				item, ok = QtWidgets.QInputDialog.getText(self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
				if ok and item:
					self.cfg_server.append({
						'address': item,
						'port': 389,
						'ssl': False
					})
					self.server = None
		self.save_settings()

		# disable STARTTLS if SSL is used (otherwise, ldap3 will try to do STARTTLS on port 636)
		if(len(self.cfg_server) > 0 and self.cfg_server[0]['ssl'] == True):
			self.cfg_use_start_tls = False

		# establish server connection
		if(self.server == None):
			try:
				tls_settings = ldap3.Tls(validate=self.cfg_tls_validate, ca_certs_file=self.cfg_ca_certs_file)
				server_array = []
				for server in self.cfg_server:
					port = server['port']
					if('gc-port' in server):
						port = server['gc-port']
						self.gc_mode_on = True
					server_array.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], tls=tls_settings, get_info=ldap3.ALL))
				self.server = ldap3.ServerPool(server_array, ldap3.FIRST, active=2, exhaust=True)
			except Exception as e:
				self.show_info_dialog('Error connecting to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
				return False

		# try to bind to server via Kerberos
		try:
			if(self.cfg_use_kerberos):
				self.connection = ldap3.Connection(
					self.server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
				)
				if(self.cfg_use_start_tls): self.connection.start_tls()
				return True # return if connection created successfully
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				self.status_bar.showMessage(str(e))
				return False

		# ask for username and password for SIMPLE bind
		if(self.cfg_username == '' or self.cfg_password == ''):
			login_window = LapsLoginWindow(
				username = propose_username(self.cfg_domain) if self.cfg_username == '' else self.cfg_username,
				server = "\n".join(compile_server_uris(self.cfg_server))
			)
			if(login_window.exec() != QtWidgets.QDialog.DialogCode.Accepted):
				return False
			self.connection = None
			self.cfg_username = login_window.txt_username.text()
			self.cfg_password = login_window.txt_password.text()
			self.save_settings()

		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(
				self.server,
				user=self.cfg_username,
				password=self.cfg_password,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
			)
			if(self.cfg_use_start_tls): self.connection.start_tls()
		except Exception as e:
			if(isinstance(e, ldap3.core.exceptions.LDAPServerPoolExhaustedError)):
				self.status_bar.showMessage(str(e))
				return False
			self.cfg_password = ''
			self.show_info_dialog('Error binding to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
			return False

		return True # return if connection created successfully

	def reconnect_for_attribute_query(self):
		# global catalog was not used for search - we can use the same connection for attribute query
		if(not self.gc_mode_on): return True
		# global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
		# -> that's why we need to establish a new connection to the "normal" LDAP port
		# LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
		tls_settings = ldap3.Tls(validate=self.cfg_tls_validate, ca_certs_file=self.cfg_ca_certs_file)
		server_array = []
		for server in self.cfg_server:
			server_array.append(ldap3.Server(server['address'], port=server['port'], use_ssl=server['ssl'], tls=tls_settings, get_info=ldap3.ALL))
		server = ldap3.ServerPool(server_array, ldap3.FIRST, active=True, exhaust=True)
		# try to bind to server via Kerberos
		try:
			if(self.cfg_use_kerberos):
				self.connection = ldap3.Connection(server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.GSSAPI,
					auto_referrals=True,
					auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
				)
				if(self.cfg_use_start_tls): self.connection.start_tls()
				return True
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))
		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(server,
				user=self.cfg_username,
				password=self.cfg_password,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.cfg_use_start_tls else True)
			)
			if(self.cfg_use_start_tls): self.connection.start_tls()
			return True
		except Exception as e:
			self.show_info_dialog('Error binding to LDAP server', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)
			return False

	def create_ldap_base(self, conn):
		if self.cfg_domain:
			# convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
			search_base = ''
			base = self.cfg_domain.split('.')
			for b in base:
				search_base += 'DC=' + b + ','
			return search_base[:-1]
		elif conn.server.info and 'defaultNamingContext' in conn.server.info.raw:
			return conn.server.info.raw['defaultNamingContext'][0].decode('utf-8')
		else:
			raise Exception('Could not create LDAP search base: reading defaultNamingContext from LDAP directory failed and no domain given.')

	def get_connection_string(self):
		return str(self.connection.server.host)+' '+str(self.connection.user)

	def load_settings(self):
		if(not path.isdir(self.cfg_dir)):
			makedirs(self.cfg_dir, exist_ok=True)
		# protect temporary .remmina file by limiting access to our config folder
		if(self.PLATFORM == 'linux'): os.chmod(self.cfg_dir, 0o700)

		dct_preset_settings = {}
		dct_user_settings = {}
		cfg_json = {}

		try:
			if(path.isfile(self.cfg_path)):
				with open(self.cfg_path) as f:
					dct_user_settings = json.load(f)
					cfg_json = dct_user_settings
			if(path.isfile(self.cfg_preset_path)):
				with open(self.cfg_preset_path) as f:
					dct_preset_settings = json.load(f)
					# use preset config if version is higher or user settings are empty
					if(dct_preset_settings.get('version', 0) > dct_user_settings.get('version', 0)
					or dct_user_settings == {}):
						cfg_json = dct_preset_settings

			self.cfg_version = cfg_json.get('version', self.cfg_version)
			self.cfg_use_kerberos = cfg_json.get('use-kerberos', self.cfg_use_kerberos)
			self.cfg_use_start_tls = cfg_json.get('use-starttls', self.cfg_use_start_tls)
			self.cfg_server = cfg_json.get('server', self.cfg_server)
			self.cfg_domain = cfg_json.get('domain', self.cfg_domain)
			self.cfg_ldap_query = cfg_json.get('ldap-query', self.cfg_ldap_query)
			self.cfg_username = cfg_json.get('username', self.cfg_username)
			self.cfg_ca_certs_file = cfg_json.get('ca-certs-file', self.cfg_ca_certs_file)
			self.cfg_tls_validate = cfg_json.get('tls-validate', self.cfg_tls_validate)
			self.cfg_ldap_attribute_password = cfg_json.get('ldap-attribute-password', self.cfg_ldap_attribute_password)
			self.cfg_ldap_attribute_password_expiry = cfg_json.get('ldap-attribute-password-expiry', self.cfg_ldap_attribute_password_expiry)
			self.cfg_ldap_attribute_password_history = cfg_json.get('ldap-attribute-password-history', self.cfg_ldap_attribute_password_history)
			tmp_ldap_attributes = cfg_json.get('ldap-attributes', self.cfg_ldap_attributes)
			self.cfg_connect_username = str(cfg_json.get('connect-username', self.cfg_connect_username))
			self.cfg_use_autotype_enter = cfg_json.get('use-autotype-enter', self.cfg_use_autotype_enter)
			if(isinstance(tmp_ldap_attributes, list) or isinstance(tmp_ldap_attributes, dict)):
				self.cfg_ldap_attributes = tmp_ldap_attributes
		except Exception as e:
			self.show_info_dialog('Error loading settings file', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)

	def save_settings(self):
		try:
			# do not save auto-discovered servers to config - should be queried every time
			save_servers = []
			for server in self.cfg_server:
				if not server.get('auto-discovered', False):
					save_servers.append(server)

			with open(self.cfg_path, 'w') as json_file:
				json.dump({
					'version': self.cfg_version,
					'use-kerberos': self.cfg_use_kerberos,
					'use-starttls': self.cfg_use_start_tls,
					'server': save_servers,
					'domain': self.cfg_domain,
					'ldap-query': self.cfg_ldap_query,
					'username': self.cfg_username,
					'ca-certs-file': self.cfg_ca_certs_file,
					'tls-validate': self.cfg_tls_validate,
					'ldap-attribute-password': self.cfg_ldap_attribute_password,
					'ldap-attribute-password-expiry': self.cfg_ldap_attribute_password_expiry,
					'ldap-attribute-password-history': self.cfg_ldap_attribute_password_history,
					'ldap-attributes': self.cfg_ldap_attributes,
					'connect-username': self.cfg_connect_username,
					'use-autotype-enter': self.cfg_use_autotype_enter,
				}, json_file, indent=4)
		except Exception as e:
			self.show_info_dialog('Error saving settings file', str(e), icon=QtWidgets.QMessageBox.Icon.Critical)

	def show_info_dialog(self, title, text, additional_text='', icon=QtWidgets.QMessageBox.Icon.Information):
		print('Dialog:', title, ':', text, ':', additional_text, ':', icon)
		msg = QtWidgets.QMessageBox()
		msg.setIcon(icon)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additional_text)
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
