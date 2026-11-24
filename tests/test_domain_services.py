"""
Tests for Workstation Domain Services Decomposition (Phase 8).
"""

import unittest

from workstation.core.workstation import TerminalWorkstation
from workstation.services.cipher_service import CipherService
from workstation.services.corpus_service import CorpusService
from workstation.services.assistant_service import AssistantService
from workstation.services.system_service import SystemService
from workstation.core.results import GematriaResult, HardwareResult


class TestDomainServices(unittest.TestCase):
    """Verify clean architectural domain service composition in TerminalWorkstation."""

    def setUp(self):
        self.ws = TerminalWorkstation()

    def test_services_composition(self):
        self.assertIsInstance(self.ws.ciphers, CipherService)
        self.assertIsInstance(self.ws.corpus, CorpusService)
        self.assertIsInstance(self.ws.assistant, AssistantService)
        self.assertIsInstance(self.ws.system, SystemService)

    def test_cipher_service_delegation(self):
        res_direct = self.ws.ciphers.run_gematria("WELCOME")
        res_ws = self.ws.run_gematria("WELCOME")
        self.assertIsInstance(res_direct, GematriaResult)
        self.assertEqual(res_direct.prime_sum, 317)
        self.assertEqual(res_direct, res_ws)

    def test_system_service_delegation(self):
        res_direct = self.ws.system.run_hardware()
        res_ws = self.ws.run_hardware()
        self.assertIsInstance(res_direct, HardwareResult)
        self.assertEqual(res_direct["metal_gpu"], res_ws["metal_gpu"])
        self.assertEqual(res_direct["neural_engine"], res_ws["neural_engine"])


if __name__ == "__main__":
    unittest.main()
