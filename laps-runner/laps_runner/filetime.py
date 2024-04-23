#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime


# Microsoft Timestamp Conversion

EPOCH_TIMESTAMP         = 11644473600  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

def dt_to_filetime(dt):
	# dt.timestamp() returns UTC time as expected by the LDAP server
	return int((dt.timestamp() + EPOCH_TIMESTAMP) * HUNDREDS_OF_NANOSECONDS)

def filetime_to_dt(ft):
	# ft is in UTC, fromtimestamp() converts to local time
	return datetime.fromtimestamp(int((ft / HUNDREDS_OF_NANOSECONDS) - EPOCH_TIMESTAMP))
