"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

Tests for the public API exposed in __init__.py
"""

import os
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from botocore.credentials import Credentials

import aws_bedrock_token_generator
from aws_bedrock_token_generator import provide_token


class TestInitModule(unittest.TestCase):
    """
    Tests for the public API exposed in __init__.py

    This tests the main entry point that users will interact with.
    """

    def setUp(self) -> None:
        """Setup test credentials."""
        self.credentials = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        self.region = "us-west-2"

    def test_module_exports(self) -> None:
        """Test that the module exports the expected symbols."""
        # Test __all__ exports
        expected_exports = ["BedrockTokenGenerator", "provide_token"]
        self.assertEqual(aws_bedrock_token_generator.__all__, expected_exports)

        # Test that symbols are actually available
        self.assertTrue(hasattr(aws_bedrock_token_generator, "BedrockTokenGenerator"))
        self.assertTrue(hasattr(aws_bedrock_token_generator, "provide_token"))

        # Test metadata
        self.assertEqual(aws_bedrock_token_generator.__version__, "1.1.0")
        self.assertEqual(aws_bedrock_token_generator.__author__, "Amazon Web Services")
        self.assertEqual(
            aws_bedrock_token_generator.__email__,
            "aws-bedrock-token-generator@amazon.com",
        )

    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_delegates_correctly(self, mock_session_class) -> None:
        """Test that provide_token works correctly with mocked session."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session

        test_region = "us-east-1"
        test_provider = Mock()
        test_provider.load.return_value = self.credentials
        test_expiry = timedelta(hours=6)

        # Act
        result = provide_token(
            region=test_region,
            aws_credentials_provider=test_provider,
            expiry=test_expiry,
        )

        # Assert
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("bedrock-api-key-"))
        test_provider.load.assert_called_once()

    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_with_defaults(self, mock_session_class) -> None:
        """Test provide_token with default parameters."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session

        # Act
        with patch.dict(os.environ, {"AWS_REGION": "us-east-1"}):
            result = provide_token()

        # Assert
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("bedrock-api-key-"))
        mock_session.get_credentials.assert_called_once()

    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_with_partial_parameters(self, mock_session_class) -> None:
        """Test provide_token with some parameters specified."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session
        test_region = "eu-west-1"

        # Act
        result = provide_token(region=test_region)

        # Assert
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("bedrock-api-key-"))
        mock_session.get_credentials.assert_called_once()

    def test_provide_token_propagates_exceptions(self) -> None:
        """Test that provide_token properly propagates exceptions from the underlying implementation."""
        # Test ValueError propagation - no region
        with patch.dict(os.environ, {}, clear=True):  # Clear all environment variables
            with self.assertRaises(ValueError) as context:
                provide_token()  # No region provided and no AWS_REGION env var

            self.assertIn("Region must be provided", str(context.exception))

        # Test ValueError propagation - invalid expiry
        with self.assertRaises(ValueError) as context:
            provide_token(region="us-east-1", expiry=timedelta(hours=13))

        self.assertIn("Token expiry must be greater than zero", str(context.exception))

        # Test RuntimeError propagation - no credentials
        mock_provider = Mock()
        mock_provider.load.return_value = None

        with self.assertRaises(RuntimeError) as context:
            provide_token(region="us-east-1", aws_credentials_provider=mock_provider)

        self.assertIn("No AWS credentials found", str(context.exception))

    def test_provide_token_function_signature(self) -> None:
        """Test that provide_token has the correct function signature."""
        import inspect

        sig = inspect.signature(provide_token)
        params = sig.parameters

        # Check parameter names
        expected_params = ["region", "aws_credentials_provider", "expiry"]
        self.assertEqual(list(params.keys()), expected_params)

        # Check parameter defaults
        self.assertIsNone(params["region"].default)
        self.assertIsNone(params["aws_credentials_provider"].default)
        self.assertEqual(params["expiry"].default, timedelta(hours=12))

        # Check return annotation
        self.assertEqual(sig.return_annotation, str)

    def test_provide_token_docstring(self) -> None:
        """Test that provide_token has proper documentation."""
        docstring = provide_token.__doc__

        self.assertIsNotNone(docstring)
        self.assertIn("Generate a short-lived AWS Bedrock bearer token", docstring)
        self.assertIn("Args:", docstring)
        self.assertIn("Returns:", docstring)
        self.assertIn("Raises:", docstring)
        self.assertIn("region:", docstring)
        self.assertIn("aws_credentials_provider:", docstring)
        self.assertIn("expiry:", docstring)

    def test_import_patterns(self) -> None:
        """Test different import patterns work correctly."""
        # Test direct import
        from aws_bedrock_token_generator import \
            provide_token as direct_provide_token

        self.assertEqual(provide_token, direct_provide_token)

        # Test module import
        import aws_bedrock_token_generator as btg

        self.assertEqual(provide_token, btg.provide_token)

        # Test BedrockTokenGenerator import
        from aws_bedrock_token_generator import BedrockTokenGenerator

        self.assertIsNotNone(BedrockTokenGenerator)

    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_type_hints(self, mock_session_class) -> None:
        """Test that provide_token works with proper type hints."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session
        mock_provider = Mock()
        mock_provider.load.return_value = self.credentials

        # Act - This should not raise any type-related errors
        result = provide_token(
            region="us-west-2",
            aws_credentials_provider=mock_provider,
            expiry=timedelta(minutes=30),
        )

        # Assert
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("bedrock-api-key-"))

    def test_module_level_imports(self) -> None:
        """Test that module-level imports are working correctly."""
        # Test that we can access the imported classes/functions
        from aws_bedrock_token_generator import BedrockTokenGenerator
        from aws_bedrock_token_generator.token_generator import \
            BedrockTokenGenerator as DirectBedrockTokenGenerator

        # They should be the same class
        self.assertEqual(BedrockTokenGenerator, DirectBedrockTokenGenerator)

        # Test that timedelta is available (used in default parameter)
        self.assertEqual(timedelta(hours=12).total_seconds(), 43200)

    @patch.dict(os.environ, {"AWS_REGION": "us-east-1"})
    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_with_defaults_detailed(self, mock_session_class) -> None:
        """Test provide_token with default parameters (detailed version)."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session

        # Act
        token = provide_token()

        # Assert
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith("bedrock-api-key-"))
        mock_session.get_credentials.assert_called_once()

    @patch("aws_bedrock_token_generator.Session")
    def test_provide_token_with_region_detailed(self, mock_session_class) -> None:
        """Test provide_token with explicit region (detailed version)."""
        # Arrange
        mock_session = Mock()
        mock_session.get_credentials.return_value = self.credentials
        mock_session_class.return_value = mock_session

        # Act
        token = provide_token(region="us-west-2")

        # Assert
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith("bedrock-api-key-"))
        mock_session.get_credentials.assert_called_once()

    def test_provide_token_with_credentials_provider_detailed(self) -> None:
        """Test provide_token with explicit credentials provider (detailed version)."""
        # Arrange
        mock_provider = Mock()
        mock_provider.load.return_value = self.credentials

        # Act
        token = provide_token(region="us-west-2", aws_credentials_provider=mock_provider)

        # Assert
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith("bedrock-api-key-"))
        mock_provider.load.assert_called_once()

    def test_provide_token_with_custom_expiry_detailed(self) -> None:
        """Test provide_token with custom expiry duration (detailed version)."""
        # Arrange
        mock_provider = Mock()
        mock_provider.load.return_value = self.credentials
        custom_expiry = timedelta(hours=6)

        # Act
        token = provide_token(
            region="us-west-2",
            aws_credentials_provider=mock_provider,
            expiry=custom_expiry,
        )

        # Assert
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith("bedrock-api-key-"))
        mock_provider.load.assert_called_once()

    def test_provide_token_no_region_raises_error_detailed(self) -> None:
        """Test that provide_token raises error when no region is available (detailed version)."""
        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            # Act & Assert
            with self.assertRaises(ValueError) as context:
                provide_token()

            self.assertIn("Region must be provided", str(context.exception))

    def test_provide_token_invalid_expiry_raises_error_detailed(self) -> None:
        """Test that provide_token raises error for invalid expiry (detailed version)."""
        # Test: Exceeds maximum
        with self.assertRaises(ValueError):
            provide_token(
                region="us-west-2",
                expiry=timedelta(hours=13),  # Exceeds maximum of 12 hours
            )

        # Test: Negative duration
        with self.assertRaises(ValueError):
            provide_token(region="us-west-2", expiry=timedelta(seconds=-1))  # Negative duration

    def test_provide_token_no_credentials_raises_error_detailed(self) -> None:
        """Test that provide_token raises error when no credentials are found (detailed version)."""
        # Arrange
        mock_provider = Mock()
        mock_provider.load.return_value = None

        # Act & Assert
        with self.assertRaises(RuntimeError) as context:
            provide_token(region="us-west-2", aws_credentials_provider=mock_provider)

        self.assertIn("No AWS credentials found", str(context.exception))
        mock_provider.load.assert_called_once()


if __name__ == "__main__":
    unittest.main()
