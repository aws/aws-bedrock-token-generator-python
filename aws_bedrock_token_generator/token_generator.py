"""
AWS Bedrock Token Generator

This module provides the BedrockTokenGenerator class for generating short-term bearer tokens
for AWS Bedrock API authentication.
"""

import base64
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


class BedrockTokenGenerator:
    DEFAULT_HOST: str = "bedrock.amazonaws.com"
    DEFAULT_URL: str = "https://bedrock.amazonaws.com/"
    SERVICE_NAME: str = "bedrock"
    AUTH_PREFIX: str = "bedrock-api-key-"
    TOKEN_VERSION: str = "&Version=1"
    TOKEN_DURATION: int = 43200  # 12 hours in seconds

    def __init__(self) -> None:
        pass

    def get_token(self, credentials: Credentials, region: str) -> str:
        if not credentials:
            raise ValueError("Credentials cannot be None")
        
        if not region or not isinstance(region, str):
            raise ValueError("Region must be a non-empty string")

        request = AWSRequest(
            method='POST',
            url=self.DEFAULT_URL,
            headers={'host': self.DEFAULT_HOST},
            params={'Action': 'CallWithBearerToken'}
        )

        auth = SigV4QueryAuth(credentials, self.SERVICE_NAME, region, expires=self.TOKEN_DURATION)
        auth.add_auth(request)

        presigned_url = request.url.replace('https://', '') + self.TOKEN_VERSION
        encoded_token = base64.b64encode(presigned_url.encode('utf-8')).decode('utf-8')

        return f"{self.AUTH_PREFIX}{encoded_token}"
