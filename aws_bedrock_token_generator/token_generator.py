"""
AWS Bedrock Token Generator

This module provides the BedrockTokenGenerator class for generating short-term bearer tokens
for AWS Bedrock API authentication.
"""

import base64
from typing import Optional
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


class BedrockTokenGenerator:
    """
    BedrockTokenGenerator provides a lightweight utility to generate short-lived AWS Bearer tokens
    for use with the Amazon Bedrock API.

    The class exposes `generate_token()`, a stateless method that returns a fresh token
    valid for 12 hours using AWS SigV4 signing.

    Example:
        >>> from aws_bedrock_token_generator import BedrockTokenGenerator
        >>> import boto3
        >>> 
        >>> generator = BedrockTokenGenerator()
        >>> session = boto3.Session()
        >>> credentials = session.get_credentials()
        >>> token = generator.generate_token(credentials, "us-west-2")
    """

    DEFAULT_HOST: str = "bedrock.amazonaws.com"
    DEFAULT_URL: str = "https://bedrock.amazonaws.com/"
    SERVICE_NAME: str = "bedrock"
    AUTH_PREFIX: str = "bedrock-api-key-"
    TOKEN_VERSION: str = "&Version=1"

    def __init__(self) -> None:
        """
        Initialize the BedrockTokenGenerator.
        
        The generator is stateless and doesn't maintain any internal state.
        """
        pass

    def generate_token(self, credentials: Credentials, region: str) -> str:
        """
        Generates a fresh Bearer token using AWS credentials and SigV4 signing.

        Args:
            credentials (Credentials): AWS credentials to use for signing.
                Must contain access_key and secret_key. May optionally contain session_token.
            region (str): AWS region identifier (e.g., "us-west-2", "eu-west-1").

        Returns:
            str: Bearer token string valid for 12 hours, prefixed with "bedrock-api-key-".

        Raises:
            ValueError: If credentials or region are invalid.
            ClientError: If AWS service call fails.

        Example:
            >>> generator = BedrockTokenGenerator()
            >>> token = generator.generate_token(credentials, "us-west-2")
            >>> print(f"Token: {token[:30]}...")
        """
        if not credentials:
            raise ValueError("Credentials cannot be None")
        
        if not region or not isinstance(region, str):
            raise ValueError("Region must be a non-empty string")

        # Create AWS request for presigning
        request = AWSRequest(
            method='POST',
            url=self.DEFAULT_URL,
            headers={'host': self.DEFAULT_HOST},
            params={'Action': 'CallWithBearerToken'}
        )

        # Sign the request using SigV4 query string signing
        auth = SigV4QueryAuth(credentials, self.SERVICE_NAME, region)
        auth.add_auth(request)

        # Extract the presigned URL and encode it
        presigned_url = request.url.replace('https://', '') + self.TOKEN_VERSION
        encoded_token = base64.b64encode(presigned_url.encode('utf-8')).decode('utf-8')

        return f"{self.AUTH_PREFIX}{encoded_token}"
