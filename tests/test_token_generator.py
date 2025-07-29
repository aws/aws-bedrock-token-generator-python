"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

Comprehensive tests for the BedrockTokenGenerator class.
"""

import base64
import os
import unittest
from datetime import timedelta
from typing import List
from unittest.mock import Mock, patch

from botocore.credentials import Credentials

from aws_bedrock_token_generator import BedrockTokenGenerator, provide_token


class TestBedrockTokenGenerator(unittest.TestCase):
    """
    Comprehensive tests for the BedrockTokenGenerator class.

    Tests cover token generation with various credentials and regions,
    token format validation, and error cases.
    """

    def setUp(self) -> None:
        """Setup test credentials and token generator instance."""
        self.token_generator = BedrockTokenGenerator()
        self.credentials = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        self.region = "us-west-2"

    def test_get_token_returns_non_null_token(self) -> None:
        """Test that get_token returns a non-null token."""
        # Act
        token = self.token_generator.get_token(self.credentials, self.region)

        # Assert
        self.assertIsNotNone(token, "Token should not be null")
        self.assertTrue(len(token) > 0, "Token should not be empty")

    def test_get_token_starts_with_correct_prefix(self) -> None:
        """Test that the token starts with the correct prefix."""
        # Act
        token = self.token_generator.get_token(self.credentials, self.region)

        # Assert
        self.assertTrue(
            token.startswith("bedrock-api-key-"),
            "Token should start with the correct prefix",
        )

    def test_get_token_with_different_regions(self) -> None:
        """Test token generation with different regions."""
        regions: List[str] = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]

        for region in regions:
            with self.subTest(region=region):
                # Act
                token = self.token_generator.get_token(self.credentials, region)

                # Assert
                self.assertIsNotNone(token, f"Token should not be null for region: {region}")
                self.assertTrue(
                    token.startswith("bedrock-api-key-"),
                    f"Token should start with the correct prefix for region: {region}",
                )

    def test_get_token_is_base64_encoded(self) -> None:
        """Test that the token is properly Base64 encoded."""
        # Act
        token = self.token_generator.get_token(self.credentials, self.region)

        # Assert
        token_without_prefix = token[len("bedrock-api-key-") :]

        # This will raise an exception if the string is not valid Base64
        try:
            decoded = base64.b64decode(token_without_prefix)
            self.assertIsNotNone(decoded, "Decoded token should not be null")
        except Exception as e:
            self.fail(f"Token is not valid Base64: {e}")

    def test_get_token_contains_version_info(self) -> None:
        """Test that the decoded token contains version information."""
        # Act
        token = self.token_generator.get_token(self.credentials, self.region)

        # Assert
        token_without_prefix = token[len("bedrock-api-key-") :]
        decoded = base64.b64decode(token_without_prefix)
        decoded_string = decoded.decode("utf-8")
        self.assertIn(
            "&Version=1",
            decoded_string,
            "Decoded token should contain version information",
        )

    def test_get_token_different_credentials_produce_different_tokens(self) -> None:
        """Test that different credentials produce different tokens."""
        # Arrange
        credentials1 = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        credentials2 = Credentials(
            access_key="AKIAI44QH8DHBEXAMPLE",
            secret_key="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
        )

        # Act
        token1 = self.token_generator.get_token(credentials1, self.region)
        token2 = self.token_generator.get_token(credentials2, self.region)

        # Assert
        self.assertNotEqual(token1, token2, "Different credentials should produce different tokens")

    def test_get_token_with_session_token(self) -> None:
        """Test token generation with session token (temporary credentials)."""
        # Arrange
        credentials_with_token = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            token="AQoDYXdzEJr...<remainder of security token>",
        )

        # Act
        token = self.token_generator.get_token(credentials_with_token, self.region)

        # Assert
        self.assertIsNotNone(token, "Token should not be null with session token")
        self.assertTrue(
            token.startswith("bedrock-api-key-"),
            "Token should start with the correct prefix",
        )

    # Original API test cases

    def test_case1_pass_credentials_and_region(self) -> None:
        """Case 1: Pass credentials and region -> pass."""
        # Act
        token = self.token_generator.get_token(self.credentials, self.region)

        # Assert
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith("bedrock-api-key-"))

    def test_case2_no_credentials_with_region(self) -> None:
        """Case 2: Don't pass credentials but pass in a region -> error."""
        # Act & Assert
        with self.assertRaises(ValueError) as context:
            self.token_generator.get_token(None, self.region)

        # Check for the specific error message
        self.assertIn("Credentials cannot be None", str(context.exception))

    def test_case3_credentials_without_region(self) -> None:
        """Case 3: Don't pass in region but passes credentials -> error."""
        # Act & Assert
        with self.assertRaises(ValueError) as context:
            self.token_generator.get_token(self.credentials, None)

        # Check for the specific error message
        self.assertIn("Region must be a non-empty string", str(context.exception))

        with self.assertRaises(ValueError) as context:
            self.token_generator.get_token(self.credentials, "")

        # Check for the specific error message
        self.assertIn("Region must be a non-empty string", str(context.exception))

    def test_original_api_compatibility(self) -> None:
        """Test compatibility with the original API."""
        # Arrange - Create a new instance with no parameters
        original_style_generator = BedrockTokenGenerator()

        # Act - Call get_token with credentials and region
        token = original_style_generator.get_token(self.credentials, self.region)

        # Assert - Basic validation
        self.assertIsNotNone(token, "Token should not be null")
        self.assertTrue(
            token.startswith("bedrock-api-key-"),
            "Token should start with the correct prefix",
        )

        # Assert - Verify token format
        token_without_prefix = token[len("bedrock-api-key-") :]
        decoded = base64.b64decode(token_without_prefix)
        decoded_string = decoded.decode("utf-8")

        # Assert - Verify token content
        self.assertIn(
            "&Version=1",
            decoded_string,
            "Decoded token should contain version information",
        )
        self.assertIn(
            "X-Amz-Expires=43200",
            decoded_string,
            "Decoded token should have the correct expiry duration (12 hours)",
        )

    def test_get_token_vs_provide_token_consistency(self) -> None:
        """Test that get_token and provide_token produce identical tokens for same inputs."""
        # Arrange
        mock_provider = Mock()
        mock_provider.load.return_value = self.credentials

        # Act - Generate token using old API
        token1 = self.token_generator.get_token(self.credentials, self.region)

        # Act - Generate token using new API
        token2 = provide_token(
            region=self.region,
            aws_credentials_provider=mock_provider,
            expiry=timedelta(hours=12),  # Default expiry matches get_token
        )

        # Assert - Both APIs should produce identical tokens
        self.assertEqual(
            token1,
            token2,
            "Both get_token() and provide_token() should produce identical tokens for same inputs",
        )

        # Assert - Both tokens should have same format
        self.assertTrue(
            token1.startswith("bedrock-api-key-"),
            "Token from get_token should have correct prefix",
        )
        self.assertTrue(
            token2.startswith("bedrock-api-key-"),
            "Token from provide_token should have correct prefix",
        )

        # Assert - Both tokens should have same length
        self.assertEqual(len(token1), len(token2), "Both tokens should have identical length")

    def test_get_token_vs_provide_token_with_custom_expiry(self) -> None:
        """Test API consistency with custom expiry duration."""
        # Arrange
        mock_provider = Mock()
        mock_provider.load.return_value = self.credentials
        custom_expiry = timedelta(hours=6)

        # Note: get_token() always uses default 12-hour expiry, so we compare
        # provide_token with default expiry vs provide_token with custom expiry
        # to ensure they produce different tokens (as expected)

        # Act
        token_default = provide_token(
            region=self.region,
            aws_credentials_provider=mock_provider,
            expiry=timedelta(hours=12),  # Default
        )

        token_custom = provide_token(
            region=self.region,
            aws_credentials_provider=mock_provider,
            expiry=custom_expiry,  # Custom
        )

        # Assert - Different expiry should produce different tokens
        self.assertNotEqual(
            token_default,
            token_custom,
            "Different expiry durations should produce different tokens",
        )

        # Assert - Both should be valid tokens
        self.assertTrue(token_default.startswith("bedrock-api-key-"))
        self.assertTrue(token_custom.startswith("bedrock-api-key-"))


if __name__ == "__main__":
    unittest.main()
