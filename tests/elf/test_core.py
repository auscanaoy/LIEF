#!/usr/bin/env python
import unittest
import lief
import tempfile
import sys
import subprocess
import stat
import os
import logging
import random
import itertools

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.WARNING)
#Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

from unittest import TestCase
from utils import get_sample


class TestCore(TestCase):
    LOGGER = logging.getLogger(__name__)

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_core(self):
        core = lief.parse(get_sample('ELF/ELF32_ARM_core_hello.core'))

        notes = core.notes

        self.assertEqual(len(notes), 6)

        # Check NT_PRPSINFO
        # =================
        prpsinfo = notes[0]

        self.assertTrue(prpsinfo.is_core)
        self.assertEqual(prpsinfo.type_core, lief.ELF.NOTE_TYPES_CORE.PRPSINFO)

        # Check details
        details = prpsinfo.details
        self.assertIsInstance(details, lief.ELF.CorePrPsInfo)
        self.assertEqual(details.file_name, "hello-exe")
        self.assertEqual(details.uid,  2000)
        self.assertEqual(details.gid,  2000)
        self.assertEqual(details.pid,  8166)
        self.assertEqual(details.ppid, 8163)
        self.assertEqual(details.pgrp, 8166)
        self.assertEqual(details.sid,  7997)

        # Check NT_PRSTATUS
        # =================
        prstatus = notes[1]
        print(prstatus)

        self.assertTrue(prstatus.is_core)
        self.assertEqual(prstatus.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)

        arm_vfp  = notes[2]
        siginfo  = notes[3]
        auxv     = notes[4]
        files    = notes[5]



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
