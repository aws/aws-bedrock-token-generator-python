"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

Comprehensive tests for the BedrockTokenGenerator class.
"""

import base64
import unittest
from typing import List
from unittest.mock import Mock

from botocore.credentials import Credentials
from aws_bedrock_token_generator import BedrockTokenGenerator


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
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

    def test_generate_token_returns_non_null_token(self) -> None:
        """Test that generate_token returns a non-null token."""
        # Act
        token = self.token_generator.generate_token(self.credentials, "us-west-2")
        
        # Assert
        self.assertIsNotNone(token, "Token should not be null")
        self.assertTrue(len(token) > 0, "Token should not be empty")

    def test_generate_token_starts_with_correct_prefix(self) -> None:
        """Test that the token starts with the correct prefix."""
        # Act
        token = self.token_generator.generate_token(self.credentials, "us-west-2")
        
        # Assert
        self.assertTrue(token.startswith("bedrock-api-key-"), 
                       "Token should start with the correct prefix")

    def test_generate_token_with_different_regions(self) -> None:
        """Test token generation with different regions."""
        regions: List[str] = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]
        
        for region in regions:
            with self.subTest(region=region):
                # Act
                token = self.token_generator.generate_token(self.credentials, region)
                
                # Assert
                self.assertIsNotNone(token, f"Token should not be null for region: {region}")
                self.assertTrue(token.startswith("bedrock-api-key-"), 
                               f"Token should start with the correct prefix for region: {region}")

    def test_generate_token_is_base64_encoded(self) -> None:
        """Test that the token is properly Base64 encoded."""
        # Act
        token = self.token_generator.generate_token(self.credentials, "us-west-2")
        
        # Assert
        token_without_prefix = token[len("bedrock-api-key-"):]
        
        # This will raise an exception if the string is not valid Base64
        try:
            decoded = base64.b64decode(token_without_prefix)
            self.assertIsNotNone(decoded, "Decoded token should not be null")
        except Exception as e:
            self.fail(f"Token is not valid Base64: {e}")

    def test_generate_token_contains_version_info(self) -> None:
        """Test that the decoded token contains version information."""
        # Act
        token = self.token_generator.generate_token(self.credentials, "us-west-2")
        
        # Assert
        token_without_prefix = token[len("bedrock-api-key-"):]
        decoded = base64.b64decode(token_without_prefix)
        decoded_string = decoded.decode('utf-8')
        self.assertIn("&Version=1", decoded_string, 
                     "Decoded token should contain version information")

    def test_generate_token_different_credentials_produce_different_tokens(self) -> None:
        """Test that different credentials produce different tokens."""
        # Arrange
        credentials1 = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        credentials2 = Credentials(
            access_key="AKIAI44QH8DHBEXAMPLE",
            secret_key="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
        )
        
        # Act
        token1 = self.token_generator.generate_token(credentials1, "us-west-2")
        token2 = self.token_generator.generate_token(credentials2, "us-west-2")
        
        # Assert
        self.assertNotEqual(token1, token2, "Different credentials should produce different tokens")

    def test_generate_token_with_session_token(self) -> None:
        """Test token generation with session token (temporary credentials)."""
        # Arrange
        credentials_with_token = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            token="AQoDYXdzEJr...<remainder of security token>"
        )
        
        # Act
        token = self.token_generator.generate_token(credentials_with_token, "us-west-2")
        
        # Assert
        self.assertIsNotNone(token, "Token should not be null with session token")
        self.assertTrue(token.startswith("bedrock-api-key-"), 
                       "Token should start with the correct prefix")

    def test_generate_token_with_invalid_credentials(self) -> None:
        """Test that invalid credentials raise appropriate errors."""
        # Act & Assert
        with self.assertRaises(ValueError):
            self.token_generator.generate_token(None, "us-west-2")

    def test_generate_token_with_invalid_region(self) -> None:
        """Test that invalid region raises appropriate errors."""
        # Act & Assert
        with self.assertRaises(ValueError):
            self.token_generator.generate_token(self.credentials, "")
        
        with self.assertRaises(ValueError):
            self.token_generator.generate_token(self.credentials, None)


if __name__ == '__main__':
    unittest.main()
