"""Model configuration and factory tests with no network or real credentials."""
import importlib.util
import os
import unittest
from unittest.mock import patch, sentinel

from pydantic import ValidationError

AVAILABLE = importlib.util.find_spec("langchain_openai") is not None
if AVAILABLE:
    from agents.model_factory import ModelConfig, create_chat_model


@unittest.skipUnless(AVAILABLE, "Install the agents extra to test the model factory")
class ModelFactoryTests(unittest.TestCase):
    def test_defaults_and_frozen_config(self):
        config = ModelConfig(model="test-model")
        self.assertEqual(config.max_tokens, 256)
        self.assertEqual(config.max_retries, 0)
        self.assertEqual(config.timeout_seconds, 20.0)
        with self.assertRaises(ValidationError):
            config.model = "other"

    def test_rejects_invalid_configuration(self):
        invalid = [
            {"model": ""}, {"model": " model"},
            {"base_url": " "}, {"api_key_env": "KEY "},
            {"max_tokens": 0}, {"max_tokens": True},
            {"max_tokens": "256"}, {"max_retries": -1},
            {"timeout_seconds": 0}, {"timeout_seconds": float("inf")},
            {"timeout_seconds": float("nan")}, {"unexpected": 1},
        ]
        for fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                ModelConfig(**{"model": "test-model", **fields})

    def test_missing_or_blank_key_prevents_client_creation(self):
        config = ModelConfig(model="test-model")
        for environment in ({}, {"OPENAI_API_KEY": ""}, {"OPENAI_API_KEY": "  "}):
            with self.subTest(environment=environment):
                with patch.dict(os.environ, environment, clear=True):
                    with patch("agents.model_factory.ChatOpenAI") as client:
                        with self.assertRaises(ValueError):
                            create_chat_model(config)
                        client.assert_not_called()

    def test_whitespace_key_is_rejected_without_disclosure(self):
        config = ModelConfig(model="test-model")
        key = " fake-test-secret "
        with patch.dict(os.environ, {"OPENAI_API_KEY": key}, clear=True):
            with patch("agents.model_factory.ChatOpenAI") as client:
                with self.assertRaises(ValueError) as caught:
                    create_chat_model(config)
                self.assertNotIn(key.strip(), str(caught.exception))
                client.assert_not_called()

    def test_custom_configuration_and_key_are_forwarded(self):
        config = ModelConfig(
            model="test-model", base_url="http://localhost:1234/v1",
            api_key_env="TEST_MODEL_KEY", max_tokens=128,
            timeout_seconds=5.0, max_retries=1,
        )
        environment = {"TEST_MODEL_KEY": "fake-key", "OPENAI_API_KEY": "wrong-key"}
        with patch.dict(os.environ, environment, clear=True):
            with patch("agents.model_factory.ChatOpenAI", return_value=sentinel.model) as client:
                result = create_chat_model(config)
        self.assertIs(result, sentinel.model)
        client.assert_called_once_with(
            model="test-model", base_url="http://localhost:1234/v1",
            api_key="fake-key", max_tokens=128, timeout=5.0,
            max_retries=1, use_responses_api=False,
        )

    def test_custom_key_does_not_fall_back_to_default(self):
        config = ModelConfig(model="test-model", api_key_env="TEST_MODEL_KEY")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "fake-key"}, clear=True):
            with patch("agents.model_factory.ChatOpenAI") as client:
                with self.assertRaises(ValueError):
                    create_chat_model(config)
                client.assert_not_called()
