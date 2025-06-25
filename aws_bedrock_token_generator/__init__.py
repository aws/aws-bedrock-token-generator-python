"""
AWS Bedrock Token Generator

A lightweight library for generating short-term bearer tokens for AWS Bedrock API authentication.

This library provides the BedrockTokenGenerator class that can generate secure, time-limited
bearer tokens using AWS SigV4 signing. These tokens can be used to authenticate with
AWS Bedrock services without exposing long-term credentials.

Example:
    >>> from aws_bedrock_token_generator import BedrockTokenGenerator
    >>> import boto3
    >>> 
    >>> generator = BedrockTokenGenerator()
    >>> session = boto3.Session()
    >>> credentials = session.get_credentials()
    >>> token = generator.get_token(credentials, "us-west-2")
"""

from .token_generator import BedrockTokenGenerator

__version__ = "1.0.0"
__author__ = "Amazon Web Services"
__email__ = "aws-bedrock-token-generator@amazon.com"
__all__ = ["BedrockTokenGenerator"]
