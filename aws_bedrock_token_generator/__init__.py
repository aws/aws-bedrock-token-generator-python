"""
AWS Bedrock Token Generator

A lightweight library for generating short-term bearer tokens for AWS Bedrock API authentication.

This library provides the BedrockTokenGenerator class that can generate secure, time-limited
bearer tokens using AWS SigV4 signing.
Recommended usage:
    >>> from aws_bedrock_token_generator import provide_token
    >>> token = provide_token()
"""

import os
from datetime import timedelta
from typing import Optional

from botocore.credentials import CredentialProvider
from botocore.session import Session

from .token_generator import (TOKEN_DURATION, BedrockTokenGenerator,
                              _generate_token)

__version__ = "1.1.0"
__author__ = "Amazon Web Services"
__email__ = "aws-bedrock-token-generator@amazon.com"
__all__ = ["BedrockTokenGenerator", "provide_token"]


def provide_token(
    region: Optional[str] = None,
    aws_credentials_provider: Optional[CredentialProvider] = None,
    expiry: timedelta = timedelta(hours=12),
) -> str:
    """
    Generate a short-lived AWS Bedrock bearer token.

    Args:
        region: AWS region to use. If not provided, falls back to the `AWS_REGION` environment variable.
        aws_credentials_provider: Optional credential provider. If not provided, the default AWS credential chain is used.
        expiry: Expiry duration for the token. Must be greater than 0 seconds and less than or equal to 12 hours.

    Returns:
        A bearer token string.

    Raises:
        ValueError: If region is missing or expiry is invalid.
        RuntimeError: If no valid AWS credentials are found.
    """
    region = region or os.environ.get("AWS_REGION")
    if not region:
        raise ValueError("Region must be provided or set via the AWS_REGION environment variable.")

    if (
        expiry.total_seconds() <= 0 or expiry.total_seconds() > TOKEN_DURATION
    ):  # 12 hours in seconds
        raise ValueError(
            "Token expiry must be greater than zero and less than or equal to 12 hours"
        )

    credentials = (
        aws_credentials_provider.load() if aws_credentials_provider else Session().get_credentials()
    )
    if credentials is None:
        raise RuntimeError(
            "No AWS credentials found. Check your environment or credential provider."
        )

    return _generate_token(credentials, region, int(expiry.total_seconds()))
