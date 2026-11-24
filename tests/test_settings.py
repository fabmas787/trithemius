import unittest
import os
from workstation.settings import Settings, current, set_current
import config


class TestSettingsSingleSourceOfTruth(unittest.TestCase):
    """Verify bidirectional synchronization and single source of truth between Settings and legacy config."""

    def setUp(self):
        # Reset settings to fresh baseline before each test
        self.original_settings = current()
        set_current(Settings.from_env_and_args(provider="ollama", low_spec=False))

    def tearDown(self):
        set_current(self.original_settings)

    def test_settings_to_config_propagation(self):
        s = current()
        s.provider = "groq"
        self.assertEqual(config.ACTIVE_PROVIDER, "groq")

        s.low_spec = True
        self.assertTrue(config.LOW_SPEC_MODE)

        s.default_num_ctx = 1024
        self.assertEqual(config.DEFAULT_NUM_CTX, 1024)

    def test_config_setter_to_settings_propagation(self):
        config.ACTIVE_PROVIDER = "openai"
        self.assertEqual(current().provider, "openai")

        config.LOW_SPEC_MODE = True
        self.assertTrue(current().low_spec)

        config.DEFAULT_NUM_CTX = 4096
        self.assertEqual(current().default_num_ctx, 4096)

        config.OLLAMA_HOST = "http://remote-ollama:11434"
        self.assertEqual(current().ollama_host, "http://remote-ollama:11434")

    def test_crewai_model_name_dynamic(self):
        s = current()
        s.provider = "ollama"
        s.active_model = "spark"
        self.assertEqual(config.CREWAI_MODEL_NAME, "ollama/spark")

        s.provider = "groq"
        s.active_model = "llama-3.1-8b-instant"
        self.assertEqual(config.CREWAI_MODEL_NAME, "groq/llama-3.1-8b-instant")


if __name__ == "__main__":
    unittest.main()
