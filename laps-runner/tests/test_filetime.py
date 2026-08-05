#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from datetime import datetime, timezone

from laps_runner.filetime import dt_to_filetime, filetime_to_dt


EPOCH_TIMESTAMP         = 11644473600
HUNDREDS_OF_NANOSECONDS = 10000000

class TestFiletime(unittest.TestCase):

    def test_dt_to_filetime_unix_epoch(self):
        # Unix epoch (1970-01-01 00:00:00 UTC) should map to EPOCH_TIMESTAMP * HNS
        dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        expected = EPOCH_TIMESTAMP * HUNDREDS_OF_NANOSECONDS
        self.assertEqual(dt_to_filetime(dt), expected)

    def test_filetime_to_dt_unix_epoch(self):
        ft = EPOCH_TIMESTAMP * HUNDREDS_OF_NANOSECONDS
        result = filetime_to_dt(ft)
        expected = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(result, expected)

    def test_roundtrip(self):
        # Truncate to seconds to avoid floating-point precision loss
        original = datetime(2024, 6, 15, 12, 30, 45, tzinfo=timezone.utc)
        ft = dt_to_filetime(original)
        recovered = filetime_to_dt(ft)
        self.assertEqual(original, recovered)

    def test_known_filetime_value(self):
        # 2024-01-01 00:00:00 UTC
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        ft = dt_to_filetime(dt)
        recovered = filetime_to_dt(ft)
        self.assertEqual(recovered, dt)

    def test_filetime_increases_with_time(self):
        dt1 = datetime(2020, 1, 1, tzinfo=timezone.utc)
        dt2 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.assertGreater(dt_to_filetime(dt2), dt_to_filetime(dt1))

    def test_filetime_to_dt_returns_utc(self):
        ft = EPOCH_TIMESTAMP * HUNDREDS_OF_NANOSECONDS
        result = filetime_to_dt(ft)
        self.assertEqual(result.tzinfo, timezone.utc)


if __name__ == '__main__':
    unittest.main()
