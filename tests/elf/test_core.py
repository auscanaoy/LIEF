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

    def test_core_arm(self):
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

        self.assertTrue(prstatus.is_core)
        self.assertEqual(prstatus.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)

        # Check details
        details = prstatus.details

        self.assertEqual(details.current_sig, 7)
        self.assertEqual(details.sigpend, 0)
        self.assertEqual(details.sighold, 0)
        self.assertEqual(details.pid, 8166)
        self.assertEqual(details.ppid, 0)
        self.assertEqual(details.pgrp, 0)
        self.assertEqual(details.sid, 0)

        self.assertEqual(details.utime.sec, 0)
        self.assertEqual(details.utime.usec, 0)

        self.assertEqual(details.stime.sec, 0)
        self.assertEqual(details.stime.usec, 0)

        self.assertEqual(details.cutime.sec, 0)
        self.assertEqual(details.cutime.usec, 0)

        self.assertEqual(details.cstime.sec, 0)
        self.assertEqual(details.cstime.usec, 0)


        reg_ctx = details.register_context
        self.assertEqual(len(reg_ctx), 17)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R0], 0xaad75074)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R1], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R2], 0xb)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R3], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R4], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R5], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R6], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R7], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R8], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R9], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R10], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R11], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R12], 0xA)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R13], 1)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R14], 0xf7728841)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.ARM_R15], 0xaad7507c)
        self.assertEqual(details.get(lief.ELF.CorePrStatus.REGISTERS.ARM_CPSR), 0x60010010)

        arm_vfp  = notes[2]
        siginfo  = notes[3]
        auxv     = notes[4]

        # Check NT_FILE
        # =================
        note = notes[5]

        self.assertTrue(note.is_core)
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.FILE)

        # Check details
        details = note.details
        files   = details.files

        self.assertEqual(len(files), details.count)
        self.assertEqual(21, details.count)

        self.assertEqual(files[0].start, 0xaad74000)
        self.assertEqual(files[0].end,   0xaad78000)
        self.assertEqual(files[0].file_ofs, 0)
        self.assertEqual(files[0].path, "/data/local/tmp/hello-exe")

        self.assertEqual(files[-1].start, 0xf77a1000)
        self.assertEqual(files[-1].end,   0xf77a2000)
        self.assertEqual(files[-1].file_ofs, 0x8a000)
        self.assertEqual(files[-1].path, "/system/bin/linker")


    def test_core_arm64(self):
        core = lief.parse(get_sample('ELF/ELF64_AArch64_core_hello.core'))

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
        self.assertEqual(details.pid,  8104)
        self.assertEqual(details.ppid, 8101)
        self.assertEqual(details.pgrp, 8104)
        self.assertEqual(details.sid,  7997)

        # Check NT_PRSTATUS
        # =================
        prstatus = notes[1]

        self.assertTrue(prstatus.is_core)
        self.assertEqual(prstatus.type_core, lief.ELF.NOTE_TYPES_CORE.PRSTATUS)

        # Check details
        details = prstatus.details

        self.assertEqual(details.current_sig, 5)
        self.assertEqual(details.sigpend, 0)
        self.assertEqual(details.sighold, 0)
        self.assertEqual(details.pid, 8104)
        self.assertEqual(details.ppid, 0)
        self.assertEqual(details.pgrp, 0)
        self.assertEqual(details.sid, 0)

        self.assertEqual(details.utime.sec, 0)
        self.assertEqual(details.utime.usec, 0)

        self.assertEqual(details.stime.sec, 0)
        self.assertEqual(details.stime.usec, 0)

        self.assertEqual(details.cutime.sec, 0)
        self.assertEqual(details.cutime.usec, 0)

        self.assertEqual(details.cstime.sec, 0)
        self.assertEqual(details.cstime.usec, 0)


        reg_ctx = details.register_context
        self.assertEqual(len(reg_ctx), 34)

        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X0],  0x5580b86f50)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X1],  0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X2],  0x1)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X3],  0x7fb7e2e160)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X4],  0x7fb7e83030)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X5],  0x4)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X6],  0x6f6c2f617461642f)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X7],  0x2f706d742f6c6163)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X8],  0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X9],  0xa)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X10], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X11], 0xA)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X12], 0x0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X13], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X14], 0x878ca62ae01a9a5)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X15], 0x7fb7e7a000)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X16], 0x7fb7c132c8)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X17], 0x7fb7bb0adc)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X18], 0x7fb7c1e000)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X19], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X20], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X21], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X22], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X23], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X24], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X25], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X26], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X27], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X28], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X29], 0)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X30], 0x7fb7eb6068)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_X31], 0x7ffffff950)
        self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.AARCH64_PC],  0x5580b86f50)

        arm_vfp  = notes[2]
        siginfo  = notes[3]
        auxv     = notes[4]

        # Check NT_FILE
        # =================
        note = notes[5]

        self.assertTrue(note.is_core)
        self.assertEqual(note.type_core, lief.ELF.NOTE_TYPES_CORE.FILE)

        # Check details
        details = note.details
        files   = details.files

        self.assertEqual(len(files), details.count)
        self.assertEqual(22, details.count)

        self.assertEqual(files[0].start, 0x5580b86000)
        self.assertEqual(files[0].end,   0x5580b88000)
        self.assertEqual(files[0].file_ofs, 0)
        self.assertEqual(files[0].path, "/data/local/tmp/hello-exe")

        self.assertEqual(files[-1].start, 0x7fb7f8c000)
        self.assertEqual(files[-1].end,   0x7fb7f8d000)
        self.assertEqual(files[-1].file_ofs, 0xf8000)
        self.assertEqual(files[-1].path, "/system/bin/linker64")

    def test_core_write(self):
        core = lief.parse(get_sample('ELF/ELF64_x86-64_core_hello.core'))
        note = core.notes[1]
        details = note.details

        details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP] = 0xBADC0DE

        with tempfile.NamedTemporaryFile(prefix="", suffix=".core") as f:
            core.write(f.name)

            core_new = lief.parse(f.name)

            note = core_new.notes[1]
            details = note.details

            self.assertEqual(details[lief.ELF.CorePrStatus.REGISTERS.X86_64_RIP], 0xBADC0DE)



if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
