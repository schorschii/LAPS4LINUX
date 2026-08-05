#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import json
import pathlib
import tempfile
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from laps_client.filetime import dt_to_filetime, filetime_to_dt
from laps_client import proposeUsername, compileServerUris
from laps_client.laps_cli import LapsCli


def _make_cli():
    c = LapsCli.__new__(LapsCli)
    c.gcModeOn = False
    c.server = None
    c.connection = None
    c.tmpDn = ''
    c.cfgVersion = 0
    c.cfgUseKerberos = True
    c.cfgUseStartTls = True
    c.cfgServer = []
    c.cfgDomain = 'example.com'
    c.cfgLdapQuery = '(&(objectClass=computer)(cn=%1))'
    c.cfgUsername = ''
    c.cfgPassword = ''
    c.cfgLdapAttributes = {
        'Operating System': 'operatingSystem',
        'Administrator Password': ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd'],
        'Password Expiration Date': ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'],
        'Administrator Password History': 'msLAPS-EncryptedPasswordHistory',
    }
    c.cfgLdapAttributePassword = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd']
    c.cfgLdapAttributePasswordExpiry = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
    c.cfgLdapAttributePasswordHistory = 'msLAPS-EncryptedPasswordHistory'
    c.dctResult = []
    return c


# ---------------------------------------------------------------------------
# filetime
# ---------------------------------------------------------------------------

class TestFiletime(unittest.TestCase):

    def test_filetime_roundtrip(self):
        ft = 132539136000000000  # 2021-01-01 00:00:00 UTC
        self.assertEqual(dt_to_filetime(filetime_to_dt(ft)), ft)

    def test_filetime_epoch(self):
        # Unix epoch (1970-01-01 00:00:00 UTC) = MS filetime 116444736000000000
        ft = 116444736000000000
        dt = filetime_to_dt(ft)
        self.assertEqual(dt.timestamp(), 0.0)

    def test_dt_to_filetime_increases_over_time(self):
        dt1 = datetime(2020, 1, 1)
        dt2 = datetime(2021, 1, 1)
        self.assertLess(dt_to_filetime(dt1), dt_to_filetime(dt2))


# ---------------------------------------------------------------------------
# __init__ helpers
# ---------------------------------------------------------------------------

class TestInitHelpers(unittest.TestCase):

    def test_propose_username_with_domain(self):
        with patch('laps_client.getpass.getuser', return_value='testuser'):
            self.assertEqual(proposeUsername('example.com'), 'testuser@example.com')

    def test_propose_username_no_domain(self):
        with patch('laps_client.getpass.getuser', return_value='testuser'):
            self.assertEqual(proposeUsername(None), 'testuser')

    def test_compile_server_uris_ldap(self):
        servers = [{'address': 'dc.example.com', 'port': 389, 'ssl': False}]
        self.assertEqual(compileServerUris(servers), ['ldap://dc.example.com:389'])

    def test_compile_server_uris_ldaps(self):
        servers = [{'address': 'dc.example.com', 'port': 636, 'ssl': True}]
        self.assertEqual(compileServerUris(servers), ['ldaps://dc.example.com:636'])

    def test_compile_server_uris_multiple(self):
        servers = [
            {'address': 'dc1.example.com', 'port': 389, 'ssl': False},
            {'address': 'dc2.example.com', 'port': 636, 'ssl': True},
        ]
        uris = compileServerUris(servers)
        self.assertIn('ldap://dc1.example.com:389', uris)
        self.assertIn('ldaps://dc2.example.com:636', uris)

    def test_compile_server_uris_empty(self):
        self.assertEqual(compileServerUris([]), [])


# ---------------------------------------------------------------------------
# GetAttributesAsDict
# ---------------------------------------------------------------------------

class TestGetAttributesAsDict(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_dict_input(self):
        self.cli.cfgLdapAttributes = {'OS': 'operatingSystem', 'Password': 'ms-Mcs-AdmPwd'}
        self.assertEqual(self.cli.GetAttributesAsDict(), {'OS': 'operatingSystem', 'Password': 'ms-Mcs-AdmPwd'})

    def test_list_input(self):
        self.cli.cfgLdapAttributes = ['operatingSystem', 'ms-Mcs-AdmPwd']
        self.assertEqual(self.cli.GetAttributesAsDict(), {
            'operatingSystem': 'operatingSystem',
            'ms-Mcs-AdmPwd': 'ms-Mcs-AdmPwd',
        })

    def test_empty_dict(self):
        self.cli.cfgLdapAttributes = {}
        self.assertEqual(self.cli.GetAttributesAsDict(), {})

    def test_empty_list(self):
        self.cli.cfgLdapAttributes = []
        self.assertEqual(self.cli.GetAttributesAsDict(), {})


# ---------------------------------------------------------------------------
# createLdapBase
# ---------------------------------------------------------------------------

class TestCreateLdapBase(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_simple_domain(self):
        self.cli.cfgDomain = 'example.com'
        self.assertEqual(self.cli.createLdapBase(MagicMock()), 'DC=example,DC=com')

    def test_subdomain(self):
        self.cli.cfgDomain = 'sub.example.com'
        self.assertEqual(self.cli.createLdapBase(MagicMock()), 'DC=sub,DC=example,DC=com')

    def test_fallback_to_ldap_info(self):
        self.cli.cfgDomain = None
        conn = MagicMock()
        conn.server.info.raw = {'defaultNamingContext': [b'DC=example,DC=com']}
        self.assertEqual(self.cli.createLdapBase(conn), 'DC=example,DC=com')

    def test_no_domain_no_info_raises(self):
        self.cli.cfgDomain = None
        conn = MagicMock()
        conn.server.info.raw = {}
        with self.assertRaisesRegex(Exception, 'Could not create LDAP search base'):
            self.cli.createLdapBase(conn)


# ---------------------------------------------------------------------------
# parseLapsValue
# ---------------------------------------------------------------------------

class TestParseLapsValue(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_native_laps_json(self):
        ft_hex = hex(132539136000000000)  # 2021-01-01 UTC
        laps_json = json.dumps({'n': 'Administrator', 'p': 'SecretPass!', 't': ft_hex})
        password, username, timestamp = self.cli.parseLapsValue(laps_json)
        self.assertEqual(password, 'SecretPass!')
        self.assertEqual(username, 'Administrator')
        self.assertIsNotNone(timestamp)

    def test_legacy_laps_plain_password(self):
        password, username, timestamp = self.cli.parseLapsValue('PlainPassword123')
        self.assertEqual(password, 'PlainPassword123')
        self.assertIsNone(username)
        self.assertIsNone(timestamp)

    def test_invalid_json_falls_back_to_plain(self):
        password, username, timestamp = self.cli.parseLapsValue('not-json-at-all')
        self.assertEqual(password, 'not-json-at-all')
        self.assertIsNone(username)

    def test_json_missing_keys_falls_back(self):
        raw = '{"p": "test"}'
        password, username, timestamp = self.cli.parseLapsValue(raw)
        self.assertEqual(password, raw)
        self.assertIsNone(username)


# ---------------------------------------------------------------------------
# pushResult / printResult
# ---------------------------------------------------------------------------

class TestPushAndPrintResult(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_push_result_appends(self):
        self.cli.pushResult('Password', 'abc123')
        self.assertEqual(self.cli.dctResult, [{'title': 'Password', 'value': 'abc123'}])

    def test_push_result_multiple(self):
        self.cli.pushResult('OS', 'Windows')
        self.cli.pushResult('Password', 'abc123')
        self.assertEqual(len(self.cli.dctResult), 2)

    def test_print_result_clears(self):
        self.cli.pushResult('Password', 'abc123')
        with patch('sys.stdout', new_callable=io.StringIO):
            self.cli.printResult()
        self.assertEqual(self.cli.dctResult, [])

    def test_print_result_formatted_output(self):
        self.cli.pushResult('OS', 'Windows')
        self.cli.pushResult('Password', 'abc123')
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            self.cli.printResult()
            out = mock_out.getvalue()
        self.assertIn('OS', out)
        self.assertIn('Windows', out)
        self.assertIn('Password', out)
        self.assertIn('abc123', out)

    def test_print_result_tsv(self):
        self.cli.pushResult('OS', 'Windows')
        self.cli.pushResult('Password', 'abc123')
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            self.cli.printResult(tsv=True)
            out = mock_out.getvalue().strip()
        self.assertEqual(out, 'Windows\tabc123')

    def test_print_result_aligns_columns(self):
        self.cli.pushResult('OS', 'Windows')
        self.cli.pushResult('Administrator Password', 'abc123')
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            self.cli.printResult()
            lines = [l for l in mock_out.getvalue().splitlines() if l.strip()]
        col_positions = [l.index(l.split(':')[1].lstrip()) for l in lines]
        self.assertEqual(col_positions[0], col_positions[1])


# ---------------------------------------------------------------------------
# SaveSettings / LoadSettings
# ---------------------------------------------------------------------------

class TestSaveAndLoadSettings(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = pathlib.Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _make_cli(self, **overrides):
        c = LapsCli.__new__(LapsCli)
        c.PLATFORM = 'linux'
        c.cfgDir = str(self.tmp_path)
        c.cfgPath = str(self.tmp_path / 'settings.json')
        c.cfgPresetPath = str(self.tmp_path / 'nonexistent.json')
        c.cfgVersion = 0
        c.cfgUseKerberos = True
        c.cfgUseStartTls = True
        c.cfgServer = []
        c.cfgDomain = None
        c.cfgLdapQuery = '(&(objectClass=computer)(cn=%1))'
        c.cfgUsername = ''
        c.cfgPassword = ''
        c.cfgLdapAttributePassword = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'ms-Mcs-AdmPwd']
        c.cfgLdapAttributePasswordExpiry = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
        c.cfgLdapAttributePasswordHistory = 'msLAPS-EncryptedPasswordHistory'
        c.cfgLdapAttributes = {}
        for k, v in overrides.items():
            setattr(c, k, v)
        return c

    def test_save_and_load_roundtrip(self):
        c1 = self._make_cli(cfgDomain='example.com', cfgUsername='admin', cfgVersion=2)
        c1.SaveSettings()

        c2 = self._make_cli()
        c2.LoadSettings()

        self.assertEqual(c2.cfgDomain, 'example.com')
        self.assertEqual(c2.cfgUsername, 'admin')
        self.assertEqual(c2.cfgVersion, 2)

    def test_auto_discovered_servers_not_saved(self):
        c = self._make_cli(cfgDomain='example.com', cfgServer=[
            {'address': 'dc1.example.com', 'port': 389, 'ssl': False, 'auto-discovered': True},
            {'address': 'dc2.example.com', 'port': 389, 'ssl': False},
        ])
        c.SaveSettings()

        with open(str(self.tmp_path / 'settings.json')) as f:
            saved = json.load(f)

        self.assertEqual(len(saved['server']), 1)
        self.assertEqual(saved['server'][0]['address'], 'dc2.example.com')

    def test_preset_config_used_when_higher_version(self):
        preset_path = self.tmp_path / 'preset.json'
        preset_path.write_text(json.dumps({
            'version': 5,
            'domain': 'preset.example.com',
            'use-kerberos': False,
            'use-starttls': True,
            'server': [],
            'ldap-query': '(&(objectClass=computer)(cn=%1))',
            'username': '',
            'ldap-attribute-password': [],
            'ldap-attribute-password-expiry': [],
            'ldap-attribute-password-history': '',
            'ldap-attributes': {},
        }))

        c = self._make_cli()
        c.cfgPresetPath = str(preset_path)
        c.LoadSettings()

        self.assertEqual(c.cfgDomain, 'preset.example.com')
        self.assertFalse(c.cfgUseKerberos)
        self.assertEqual(c.cfgVersion, 5)

    def test_list_ldap_attributes_loaded(self):
        attrs = ['operatingSystem', 'ms-Mcs-AdmPwd']
        c = self._make_cli()
        (self.tmp_path / 'settings.json').write_text(json.dumps({'ldap-attributes': attrs}))
        c.LoadSettings()
        self.assertEqual(c.cfgLdapAttributes, attrs)

    def test_user_settings_preferred_when_version_equal(self):
        preset_path = self.tmp_path / 'preset.json'
        preset_path.write_text(json.dumps({'version': 1, 'domain': 'preset.example.com'}))
        (self.tmp_path / 'settings.json').write_text(json.dumps({'version': 1, 'domain': 'user.example.com'}))

        c = self._make_cli()
        c.cfgPresetPath = str(preset_path)
        c.LoadSettings()

        self.assertEqual(c.cfgDomain, 'user.example.com')


# ---------------------------------------------------------------------------
# GetConnectionString
# ---------------------------------------------------------------------------

class TestGetConnectionString(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_returns_host_and_user(self):
        self.cli.connection = MagicMock()
        self.cli.connection.server.host = 'dc.example.com'
        self.cli.connection.user = 'EXAMPLE\\admin'
        self.assertEqual(self.cli.GetConnectionString(), 'dc.example.com EXAMPLE\\admin')


# ---------------------------------------------------------------------------
# SetExpiry
# ---------------------------------------------------------------------------

class TestSetExpiry(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_returns_early_when_tmpdn_empty(self):
        self.cli.tmpDn = ''
        self.cli.connection = MagicMock()
        self.cli.SetExpiry('2025-01-01 00:00:00')
        self.cli.connection.modify.assert_not_called()

    def test_returns_early_when_tmpdn_whitespace(self):
        self.cli.tmpDn = '   '
        self.cli.connection = MagicMock()
        self.cli.SetExpiry('2025-01-01 00:00:00')
        self.cli.connection.modify.assert_not_called()

    def test_calls_modify_with_list_attribute(self):
        self.cli.tmpDn = 'CN=PC01,DC=example,DC=com'
        self.cli.cfgLdapAttributePasswordExpiry = ['msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime']
        self.cli.connection = MagicMock()
        self.cli.connection.result = {'result': 0, 'message': ''}
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            self.cli.SetExpiry('2025-06-01 12:00:00')
            out = mock_out.getvalue()
        self.cli.connection.modify.assert_called_once()
        call_args = self.cli.connection.modify.call_args
        self.assertEqual(call_args[0][0], self.cli.tmpDn)
        self.assertIn('msLAPS-PasswordExpirationTime', call_args[0][1])
        self.assertIn('Expiration Date Changed Successfully', out)

    def test_calls_modify_with_string_attribute(self):
        self.cli.tmpDn = 'CN=PC01,DC=example,DC=com'
        self.cli.cfgLdapAttributePasswordExpiry = 'ms-Mcs-AdmPwdExpirationTime'
        self.cli.connection = MagicMock()
        self.cli.connection.result = {'result': 0, 'message': ''}
        with patch('sys.stdout', new_callable=io.StringIO):
            self.cli.SetExpiry('2025-06-01 12:00:00')
        self.cli.connection.modify.assert_called_once()
        self.assertIn('ms-Mcs-AdmPwdExpirationTime', self.cli.connection.modify.call_args[0][1])

    def test_modify_failure_prints_message(self):
        self.cli.tmpDn = 'CN=PC01,DC=example,DC=com'
        self.cli.cfgLdapAttributePasswordExpiry = ['msLAPS-PasswordExpirationTime']
        self.cli.connection = MagicMock()
        self.cli.connection.result = {'result': 50, 'message': 'Insufficient access rights'}
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            self.cli.SetExpiry('2025-06-01 12:00:00')
            out = mock_out.getvalue()
        self.assertIn('Unable to change expiration date', out)


# ---------------------------------------------------------------------------
# SearchComputer early-return guard
# ---------------------------------------------------------------------------

class TestSearchComputerGuard(unittest.TestCase):

    def setUp(self):
        self.cli = _make_cli()

    def test_empty_string_returns_without_connecting(self):
        self.cli.connection = MagicMock()
        self.cli.SearchComputer('')
        self.cli.connection.search.assert_not_called()

    def test_whitespace_only_returns_without_connecting(self):
        self.cli.connection = MagicMock()
        self.cli.SearchComputer('   ')
        self.cli.connection.search.assert_not_called()


if __name__ == '__main__':
    unittest.main()
