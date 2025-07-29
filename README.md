# AWS Bedrock Token Generator for Python

[![Build Status](https://github.com/aws/aws-bedrock-token-generator-python/workflows/Build/badge.svg)](https://github.com/aws/aws-bedrock-token-generator-python/actions)
[![PyPI version](https://badge.fury.io/py/aws-bedrock-token-generator.svg)](https://badge.fury.io/py/aws-bedrock-token-generator)
[![Python versions](https://img.shields.io/pypi/pyversions/aws-bedrock-token-generator.svg)](https://pypi.org/project/aws-bedrock-token-generator/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

The **AWS Bedrock Token Generator for Python** is a lightweight utility library that generates short-term bearer tokens for AWS Bedrock API authentication. This library simplifies the process of creating secure, time-limited tokens that can be used to authenticate with AWS Bedrock services without exposing long-term credentials.

## Installation

### Using pip

```bash
pip install aws-bedrock-token-generator
```

### From source

```bash
git clone https://github.com/aws/aws-bedrock-token-generator-python.git
cd aws-bedrock-token-generator-python
pip install -e .
```

## Quick Start

### Basic Usage

##### Create token with no parameters, uses default region, credentials and token expiry time (1 hour) #####

```python
from aws_bedrock_token_generator import provide_token

token = provide_token()  # uses AWS_REGION env var and default credential chain
print(f"Token: {token}")
```

##### Create token using EnvProvider credentials provider #####
```python
from aws_bedrock_token_generator import provide_token
from botocore.credentials import EnvProvider

token = provide_token(region="us-east-1", aws_credentials_provider=EnvProvider())
print(f"Token: {token}")
```

##### Create token with AssumeRole credentials provider #####
```python
from aws_bedrock_token_generator import provide_token
from botocore.credentials import AssumeRoleProvider, CanonicalNameCredentialSourcer, EnvProvider
from botocore.session import Session
from datetime import timedelta

session = Session()
assume_role_provider = AssumeRoleProvider(
  profile_name="bearertoken",
  load_config=lambda: session.full_config,
  client_creator=session.create_client,
  credential_sourcer=CanonicalNameCredentialSourcer([EnvProvider()]),
  cache={}
)

bearer_token = provide_token(
  region="us-east-1",
  aws_credentials_provider=assume_role_provider,
  expiry=timedelta(seconds=900)
)
print(f"Bearer Token: {bearer_token}")
```

## Token Format

The generated tokens follow this format:
```
bedrock-api-key-<base64-encoded-presigned-url>&Version=1
```

- **Prefix**: `bedrock-api-key-` identifies the token type
- **Payload**: Base64-encoded presigned URL with embedded credentials
- **Version**: `&Version=1` for future compatibility
- **Expiration**: The token has a default expiration of 12 hours. If the expires parameter is specified during token creation, the expiration can be configured up to a maximum of 12 hours. However, the actual token validity period will always
  be the minimum of the requested expiration time and the AWS credentials' expiry time

## Security Considerations

- **Token Expiration**: The token has a default expiration of 12 hours. If the expiry parameter is specified during token creation, the expiration can be configured up to a maximum of 12 hours. However, the actual token validity period will always
  be the minimum of the requested expiration time and the AWS credentials' expiry time. The token must be generated again once it expires,
  as it cannot be refreshed or extended
- **Secure Storage**: Store tokens securely and avoid logging them
- **Credential Management**: Use IAM roles and temporary credentials when possible
- **Network Security**: Always use HTTPS when transmitting tokens
- **Principle of Least Privilege**: Ensure underlying credentials have minimal required permissions

## Requirements

- **Python**: 3.7 or later
- **boto3**: 1.26.0 or later
- **botocore**: 1.29.0 or later

## Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/aws/aws-bedrock-token-generator-python.git
cd aws-bedrock-token-generator-python

# Install in development mode with dev dependencies
pip install -e .[dev]
```

### Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=aws_bedrock_token_generator

# Run tests with verbose output
pytest -v
```

### Code Quality

```bash
# Format code with black
black aws_bedrock_token_generator tests

# Check code style with flake8
flake8 aws_bedrock_token_generator tests

# Type checking with mypy
mypy aws_bedrock_token_generator
```

### Building Distribution

```bash
# Build wheel and source distribution
python -m build

# Install from local build
pip install dist/aws_bedrock_token_generator-*.whl
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make changes and add tests**
4. **Run tests**: `pytest`
5. **Format code**: `black .`
6. **Submit a pull request**

## Support

- **Documentation**: [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- **Issues**: [GitHub Issues](https://github.com/aws/aws-bedrock-token-generator-python/issues)
- **AWS Support**: [AWS Support Center](https://console.aws.amazon.com/support/)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [AWS SDK for Python (Boto3)](https://github.com/boto/boto3)
- [AWS Bedrock Token Generator for Java](https://github.com/aws/aws-bedrock-token-generator-java)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
