#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import getpass


def proposeUsername(domain):
	return getpass.getuser() + ('@'+domain if domain else '')
