"""
Unit tests for Trithemius Multi-Provider Streaming & Cloud API Engine.
Tests:
1. Ollama streaming (local and remote hosts, thinking & content tokens)
2. OpenAI / Groq SSE streaming (delta.content & delta.reasoning)
3. Google Gemini SSE streaming
4. Anthropic Claude SSE streaming
5. Missing API key validation and error surfacing
6. Remote Ollama custom host and bearer authorization headers
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
import scripts.providers as providers


class TestOllamaStreaming(unittest.TestCase):
    @patch("requests.post")
    def test_ollama_streaming_success(self, mock_post):
        # Mock streaming response with thinking and content tokens
        fake_chunks = [
            b'{"message": {"thinking": "Analyzing runes..."}}\n',
            b'{"message": {"content": "Liber "}}\n',
            b'{"message": {"content": "Primus"}}\n',
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = fake_chunks
        mock_post.return_value = mock_resp

        tokens = list(providers.stream_ollama(
            model="SparkLLM/Spark-X2.5-4B",
            prompt="Decode page 56",
            think=True,
            host="http://localhost:11434"
        ))

        self.assertEqual(len(tokens), 3)
        self.assertEqual(tokens[0], ("thinking", "Analyzing runes..."))
        self.assertEqual(tokens[1], ("content", "Liber "))
        self.assertEqual(tokens[2], ("content", "Primus"))

        # Verify request payload
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://localhost:11434/api/chat")
        self.assertEqual(kwargs["json"]["model"], "SparkLLM/Spark-X2.5-4B")
        self.assertTrue(kwargs["json"]["think"])

    @patch("requests.post")
    def test_remote_ollama_host_and_auth(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = [b'{"message": {"content": "Cloud response"}}\n']
        mock_post.return_value = mock_resp

        tokens = list(providers.stream_ollama(
            model="SparkLLM/Spark-X2.5-4B",
            prompt="Hello remote",
            host="https://remote-ollama.example.com",
            api_key="secret-token-123"
        ))

        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], ("content", "Cloud response"))

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://remote-ollama.example.com/api/chat")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer secret-token-123")


class TestOpenAICompatibleStreaming(unittest.TestCase):
    @patch("requests.post")
    def test_groq_streaming_success(self, mock_post):
        # Mock SSE streaming response from Groq
        sse_lines = [
            b'data: {"choices": [{"delta": {"reasoning": "Reasoning step 1"}}]}\n',
            b'data: {"choices": [{"delta": {"content": "The primes are sacred."}}]}\n',
            b'data: [DONE]\n',
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = sse_lines
        mock_post.return_value = mock_resp

        tokens = list(providers.stream_openai_compatible(
            provider="groq",
            model="llama-3.1-8b-instant",
            prompt="Explain primes",
            api_key="gsk_test12345"
        ))

        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0], ("thinking", "Reasoning step 1"))
        self.assertEqual(tokens[1], ("content", "The primes are sacred."))

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer gsk_test12345")

    def test_missing_api_key_raises_value_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                list(providers.stream_openai_compatible(
                    provider="openai",
                    model="gpt-4o-mini",
                    prompt="Hello",
                    api_key=None
                ))
            self.assertIn("No API key found for provider 'openai'", str(ctx.exception))


class TestGeminiStreaming(unittest.TestCase):
    @patch("requests.post")
    def test_gemini_streaming_success(self, mock_post):
        # Mock Gemini SSE response
        sse_lines = [
            b'data: {"candidates": [{"content": {"parts": [{"text": "Welcome "}]}}]}\n',
            b'data: {"candidates": [{"content": {"parts": [{"text": "Pilgrim."}]}}]}\n',
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = sse_lines
        mock_post.return_value = mock_resp

        tokens = list(providers.stream_gemini(
            model="gemini-1.5-flash",
            prompt="Greeting",
            api_key="gemini_test_key"
        ))

        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0], ("content", "Welcome "))
        self.assertEqual(tokens[1], ("content", "Pilgrim."))

        args, kwargs = mock_post.call_args
        self.assertIn("key=gemini_test_key", args[0])
        self.assertIn("gemini-1.5-flash:streamGenerateContent", args[0])


class TestAnthropicStreaming(unittest.TestCase):
    @patch("requests.post")
    def test_anthropic_streaming_success(self, mock_post):
        # Mock Anthropic SSE response
        sse_lines = [
            b'data: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Seek "}}\n',
            b'data: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "truth."}}\n',
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = sse_lines
        mock_post.return_value = mock_resp

        tokens = list(providers.stream_anthropic(
            model="claude-3-5-haiku-20241022",
            prompt="Seek truth",
            api_key="sk-ant-test1234"
        ))

        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0], ("content", "Seek "))
        self.assertEqual(tokens[1], ("content", "truth."))

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["x-api-key"], "sk-ant-test1234")


class TestUnifiedCompletionDispatcher(unittest.TestCase):
    @patch("scripts.providers.stream_openai_compatible")
    def test_dispatcher_routes_groq(self, mock_groq):
        mock_groq.return_value = iter([("content", "Dispatched")])
        res = list(providers.stream_completion("groq", "llama-3.1-8b-instant", "Hello"))
        self.assertEqual(res, [("content", "Dispatched")])
        mock_groq.assert_called_once()

    @patch("scripts.providers.stream_gemini")
    def test_dispatcher_routes_gemini(self, mock_gem):
        mock_gem.return_value = iter([("content", "Gemini stream")])
        res = list(providers.stream_completion("gemini", "gemini-1.5-flash", "Hello"))
        self.assertEqual(res, [("content", "Gemini stream")])
        mock_gem.assert_called_once()


class TestProviderProbe(unittest.TestCase):
    @patch("requests.get")
    def test_probe_ollama_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"models": [{"name": "SparkLLM/Spark-X2.5-4B"}]}'
        mock_resp.json.return_value = {"models": [{"name": "SparkLLM/Spark-X2.5-4B"}]}
        mock_get.return_value = mock_resp

        res = providers.probe_provider("ollama", "SparkLLM/Spark-X2.5-4B")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "OK")
        self.assertIn("Daemon online", res["details"])

    def test_probe_missing_key(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": ""}, clear=True):
            res = providers.probe_provider("groq", "llama-3.1-8b-instant")
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Missing API key", res["reason"])

    @patch("requests.get")
    def test_probe_cloud_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        with patch("config.get_api_key", return_value="gsk_fake123"):
            res = providers.probe_provider("groq", "llama-3.1-8b-instant")
            self.assertTrue(res["ok"])
            self.assertEqual(res["status"], "OK")

    @patch("requests.get")
    def test_probe_network_error_never_crashes(self, mock_get):
        mock_get.side_effect = ConnectionError("Connection refused")
        res = providers.probe_provider("ollama")
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("Connection", res["reason"])


if __name__ == "__main__":
    unittest.main()
