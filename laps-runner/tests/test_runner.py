#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import string
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


# Suppress stdout noise and syslog during import
with patch('builtins.print'), patch('logging.handlers.SysLogHandler.__init__', return_value=None):
    from laps_runner.laps_runner import LapsRunner, getCurrentPasswordHash


def make_runner():
    """Return a LapsRunner with all noisy side-effects suppressed."""
    with patch('builtins.print'), \
         patch('logging.handlers.SysLogHandler.__init__', return_value=None), \
         patch('logging.Logger.addHandler'):
        runner = LapsRunner()
    return runner


class TestGetHostname(unittest.TestCase):

    def test_returns_socket_hostname_when_none(self):
        runner = make_runner()
        runner.cfgHostname = None
        with patch('socket.gethostname', return_value='myhost.example.com'):
            self.assertEqual(runner.getHostname(), 'MYHOST')

    def test_returns_socket_hostname_when_empty(self):
        runner = make_runner()
        runner.cfgHostname = '   '
        with patch('socket.gethostname', return_value='myhost.example.com'):
            self.assertEqual(runner.getHostname(), 'MYHOST')

    def test_returns_configured_hostname_uppercased(self):
        runner = make_runner()
        runner.cfgHostname = 'workstation01'
        self.assertEqual(runner.getHostname(), 'WORKSTATION01')

    def test_strips_whitespace_from_configured_hostname(self):
        runner = make_runner()
        runner.cfgHostname = '  PC01  '
        self.assertEqual(runner.getHostname(), 'PC01')


class TestCreateLdapBase(unittest.TestCase):

    def test_simple_domain(self):
        runner = make_runner()
        runner.cfgDomain = 'example.com'
        conn = MagicMock()
        self.assertEqual(runner.createLdapBase(conn), 'DC=example,DC=com')

    def test_subdomain(self):
        runner = make_runner()
        runner.cfgDomain = 'sub.example.com'
        conn = MagicMock()
        self.assertEqual(runner.createLdapBase(conn), 'DC=sub,DC=example,DC=com')

    def test_single_label_domain(self):
        runner = make_runner()
        runner.cfgDomain = 'local'
        conn = MagicMock()
        self.assertEqual(runner.createLdapBase(conn), 'DC=local')

    def test_falls_back_to_default_naming_context(self):
        runner = make_runner()
        runner.cfgDomain = ''
        conn = MagicMock()
        conn.server.info.raw = {'defaultNamingContext': [b'DC=corp,DC=local']}
        self.assertEqual(runner.createLdapBase(conn), 'DC=corp,DC=local')

    def test_raises_when_no_domain_and_no_naming_context(self):
        runner = make_runner()
        runner.cfgDomain = ''
        conn = MagicMock()
        conn.server.info = None
        with self.assertRaises(Exception):
            runner.createLdapBase(conn)


class TestGeneratePassword(unittest.TestCase):

    def test_string_alphabet_correct_length(self):
        runner = make_runner()
        runner.cfgLength = 15
        runner.cfgAlphabet = string.ascii_letters + string.digits
        pw = runner.generatePassword()
        self.assertEqual(len(pw), 15)

    def test_string_alphabet_chars_in_set(self):
        runner = make_runner()
        runner.cfgLength = 20
        runner.cfgAlphabet = string.ascii_lowercase
        pw = runner.generatePassword()
        for ch in pw:
            self.assertIn(ch, string.ascii_lowercase)

    def test_list_alphabet_contains_char_from_each_group(self):
        runner = make_runner()
        runner.cfgLength = 10
        runner.cfgAlphabet = [string.ascii_uppercase, string.digits, string.ascii_lowercase]
        pw = runner.generatePassword()
        self.assertEqual(len(pw), 10)
        # At least one character from each group must be present
        self.assertTrue(any(c in string.ascii_uppercase for c in pw))
        self.assertTrue(any(c in string.digits for c in pw))
        self.assertTrue(any(c in string.ascii_lowercase for c in pw))

    def test_list_alphabet_total_length(self):
        runner = make_runner()
        runner.cfgLength = 12
        runner.cfgAlphabet = ['ABC', '123']
        pw = runner.generatePassword()
        self.assertEqual(len(pw), 12)

    def test_passwords_are_random(self):
        runner = make_runner()
        runner.cfgLength = 20
        runner.cfgAlphabet = string.ascii_letters + string.digits
        # Generating 10 passwords of 20 chars each: collision probability is negligible
        passwords = {runner.generatePassword() for _ in range(10)}
        self.assertGreater(len(passwords), 1)


class TestRotateAndPackMsdatetime(unittest.TestCase):

    def test_swaps_upper_lower_words(self):
        runner = make_runner()
        # Pack a known 64-bit value and verify upper/lower word swap
        value = 0x0102030405060708
        result = runner.rotate_and_pack_msdatetime(value)
        self.assertEqual(len(result), 8)
        left, right = struct.unpack('<LL', struct.pack('Q', value))
        expected = struct.pack('<LL', right, left)
        self.assertEqual(result, expected)

    def test_output_is_8_bytes(self):
        runner = make_runner()
        result = runner.rotate_and_pack_msdatetime(132000000000000000)
        self.assertEqual(len(result), 8)


class TestPrepareEnvironment(unittest.TestCase):

    def test_returns_dict(self):
        runner = make_runner()
        env = runner.prepareEnvironment()
        self.assertIsInstance(env, dict)

    def test_uses_orig_ld_library_path_when_present(self):
        runner = make_runner()
        with patch.dict(os.environ, {'LD_LIBRARY_PATH': 'pyinstaller_path', 'LD_LIBRARY_PATH_ORIG': '/usr/lib'}, clear=False):
            env = runner.prepareEnvironment()
        self.assertEqual(env.get('LD_LIBRARY_PATH'), '/usr/lib')

    def test_removes_ld_library_path_when_no_orig(self):
        runner = make_runner()
        base = {k: v for k, v in os.environ.items() if k not in ('LD_LIBRARY_PATH_ORIG', 'LD_LIBRARY_PATH')}
        base['LD_LIBRARY_PATH'] = 'some_value'
        with patch.dict(os.environ, base, clear=True):
            env = runner.prepareEnvironment()
        self.assertNotIn('LD_LIBRARY_PATH', env)


class TestGetCurrentPasswordHash(unittest.TestCase):

    def _write_shadow(self, content):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.shadow', delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_finds_hash_for_user(self):
        path = self._write_shadow(
            'daemon:*:19000:0:99999:7:::\n'
            'root:$6$abc123$hashedvalue:19000:0:99999:7:::\n'
            'nobody:*:19000:0:99999:7:::\n'
        )
        try:
            result = getCurrentPasswordHash('root', shadow_file=path)
            self.assertEqual(result, '$6$abc123$hashedvalue')
        finally:
            os.unlink(path)

    def test_raises_for_missing_user(self):
        path = self._write_shadow('daemon:*:19000:0:99999:7:::\n')
        try:
            with self.assertRaises(ValueError):
                getCurrentPasswordHash('root', shadow_file=path)
        finally:
            os.unlink(path)

    def test_raises_for_malformed_entry(self):
        path = self._write_shadow('root\n')
        try:
            with self.assertRaises(ValueError):
                getCurrentPasswordHash('root', shadow_file=path)
        finally:
            os.unlink(path)

    def test_finds_non_root_user(self):
        path = self._write_shadow(
            'root:$6$root_hash:19000:0:99999:7:::\n'
            'admin:$6$admin_hash:19000:0:99999:7:::\n'
        )
        try:
            result = getCurrentPasswordHash('admin', shadow_file=path)
            self.assertEqual(result, '$6$admin_hash')
        finally:
            os.unlink(path)


class TestLoadSettings(unittest.TestCase):

    def _write_config(self, data):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_loads_domain(self):
        path = self._write_config({'domain': 'corp.example.com'})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgDomain, 'corp.example.com')
        finally:
            os.unlink(path)

    def test_loads_server_list(self):
        path = self._write_config({
            'server': [{'address': 'dc1.corp.com', 'port': 389, 'ssl': False}]
        })
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(len(runner.cfgServer), 1)
            self.assertEqual(runner.cfgServer[0]['address'], 'dc1.corp.com')
            self.assertEqual(runner.cfgServer[0]['port'], 389)
            self.assertFalse(runner.cfgServer[0]['ssl'])
        finally:
            os.unlink(path)

    def test_loads_password_settings(self):
        path = self._write_config({
            'password-change-user': 'localadmin',
            'password-days-valid': 14,
            'password-length': 20,
            'password-alphabet': 'abc123',
        })
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgUsername, 'localadmin')
            self.assertEqual(runner.cfgDaysValid, 14)
            self.assertEqual(runner.cfgLength, 20)
            self.assertEqual(runner.cfgAlphabet, 'abc123')
        finally:
            os.unlink(path)

    def test_defaults_preserved_for_missing_keys(self):
        path = self._write_config({})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgDaysValid, 30)
            self.assertEqual(runner.cfgLength, 15)
            self.assertEqual(runner.cfgUsername, 'root')
        finally:
            os.unlink(path)

    def test_loads_ldap_attributes(self):
        path = self._write_config({
            'ldap-attribute-password': 'ms-MCS-AdmPwd',
            'ldap-attribute-password-history': 'ms-MCS-AdmPwdHistory',
            'ldap-attribute-password-expiry': 'ms-MCS-AdmPwdExpirationTime',
        })
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgLdapAttributePassword, 'ms-MCS-AdmPwd')
            self.assertEqual(runner.cfgLdapAttributePasswordHistory, 'ms-MCS-AdmPwdHistory')
            self.assertEqual(runner.cfgLdapAttributePasswordExpiry, 'ms-MCS-AdmPwdExpirationTime')
        finally:
            os.unlink(path)

    def test_loads_native_laps_flag(self):
        path = self._write_config({'native-laps': False})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertFalse(runner.cfgUseNativeLapsAttributeSchema)
        finally:
            os.unlink(path)

    def test_loads_hooks(self):
        hooks = {'notify': ['notify-send', '$PASSWORD$']}
        path = self._write_config({'hooks': hooks})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgHooks, hooks)
        finally:
            os.unlink(path)

    def test_raises_when_config_file_missing(self):
        runner = make_runner()
        runner.cfgPath = '/nonexistent/path/laps.json'
        with self.assertRaises(Exception):
            runner.LoadSettings()

    def test_loads_pam_settings(self):
        path = self._write_config({
            'pam-services': ['login', 'sshd'],
            'pam-grace-period': 60,
        })
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgPamServices, ['login', 'sshd'])
            self.assertEqual(runner.cfgPamGracePeriod, 60)
        finally:
            os.unlink(path)

    def test_loads_security_descriptor(self):
        path = self._write_config({'security-descriptor': 'S-1-5-21-123-456-789-1000'})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgSecurityDescriptor, 'S-1-5-21-123-456-789-1000')
        finally:
            os.unlink(path)

    def test_loads_history_size(self):
        path = self._write_config({'history-size': 5})
        try:
            runner = make_runner()
            runner.cfgPath = path
            runner.LoadSettings()
            self.assertEqual(runner.cfgHistorySize, 5)
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
