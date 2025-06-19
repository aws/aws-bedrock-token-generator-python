# AWS Bedrock Token Generator for Python

[![Build Status](https://github.com/aws/aws-bedrock-token-generator-python/workflows/Build/badge.svg)](https://github.com/aws/aws-bedrock-token-generator-python/actions)
[![PyPI version](https://badge.fury.io/py/aws-bedrock-token-generator.svg)](https://badge.fury.io/py/aws-bedrock-token-generator)
[![Python versions](https://img.shields.io/pypi/pyversions/aws-bedrock-token-generator.svg)](https://pypi.org/project/aws-bedrock-token-generator/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

The **AWS Bedrock Token Generator for Python** is a lightweight utility library that generates short-term bearer tokens for AWS Bedrock API authentication. This library simplifies the process of creating secure, time-limited tokens that can be used to authenticate with AWS Bedrock services without exposing long-term credentials.

## Features

- ✅ **Simple API**: Single method to generate bearer tokens
- ✅ **Secure**: Uses AWS SigV4 signing with 12-hour token expiration
- ✅ **Multi-region support**: Works with any AWS region where Bedrock is available
- ✅ **Boto3 Integration**: Seamlessly works with boto3 credential providers
- ✅ **Lightweight**: Minimal dependencies, focused functionality
- ✅ **Well-tested**: Comprehensive unit tests with multiple scenarios
- ✅ **Type hints**: Full type annotation support for better IDE experience

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

```python
from aws_bedrock_token_generator import BedrockTokenGenerator
import boto3

# Create token generator
token_generator = BedrockTokenGenerator()

# Generate token using default credentials
session = boto3.Session()
credentials = session.get_credentials()

bearer_token = token_generator.generate_token(credentials, "us-west-2")

# Use the token for API calls (valid for 12 hours)
print(f"Bearer Token: {bearer_token}")
```

### Using with Specific Credentials

```python
from botocore.credentials import Credentials

# Create specific credentials
credentials = Credentials(
    access_key="your-access-key-id",
    secret_key="your-secret-access-key"
)

# Generate token
token_generator = BedrockTokenGenerator()
bearer_token = token_generator.generate_token(credentials, "us-east-1")
```

### Using with Session Token (Temporary Credentials)

```python
from botocore.credentials import Credentials

# Create temporary credentials (e.g., from STS)
credentials = Credentials(
    access_key="your-access-key-id",
    secret_key="your-secret-access-key",
    token="your-session-token"
)

# Generate token
bearer_token = token_generator.generate_token(credentials, "eu-west-1")
```

### Using with Different Credential Providers

```python
import boto3
from botocore.credentials import InstanceMetadataProvider

# Using EC2 instance metadata
session = boto3.Session()
credentials = session.get_credentials()

# Using environment variables
session = boto3.Session()
credentials = session.get_credentials()

# Using AWS profile
session = boto3.Session(profile_name='my-profile')
credentials = session.get_credentials()

# Generate tokens with any credential provider
token_generator = BedrockTokenGenerator()
bearer_token = token_generator.generate_token(credentials, "us-west-2")
```

## API Reference

### BedrockTokenGenerator

#### `generate_token(credentials, region)`

Generates a bearer token for AWS Bedrock API authentication.

**Parameters:**
- `credentials` (botocore.credentials.Credentials): AWS credentials to use for signing
- `region` (str): AWS region identifier (e.g., "us-west-2")

**Returns:**
- `str`: A bearer token valid for 12 hours, prefixed with "bedrock-api-key-"

**Raises:**
- `ValueError`: If credentials or region are invalid
- `ClientError`: If AWS service call fails

**Example:**
```python
from aws_bedrock_token_generator import BedrockTokenGenerator
import boto3

generator = BedrockTokenGenerator()
session = boto3.Session()
credentials = session.get_credentials()
token = generator.generate_token(credentials, "us-west-2")
```

## Token Format

The generated tokens follow this format:
```
bedrock-api-key-<base64-encoded-presigned-url>&Version=1
```

- **Prefix**: `bedrock-api-key-` identifies the token type
- **Payload**: Base64-encoded presigned URL with embedded credentials
- **Version**: `&Version=1` for future compatibility
- **Expiration**: 12 hours from generation time

## Security Considerations

- **Token Expiration**: Tokens are valid for 12 hours and cannot be renewed
- **Secure Storage**: Store tokens securely and avoid logging them
- **Credential Management**: Use IAM roles and temporary credentials when possible
- **Network Security**: Always use HTTPS when transmitting tokens
- **Principle of Least Privilege**: Ensure underlying credentials have minimal required permissions

## Requirements

- **Python**: 3.7 or later
- **boto3**: 1.26.0 or later
- **botocore**: 1.29.0 or later

## Examples

### Complete Example with Error Handling

```python
from aws_bedrock_token_generator import BedrockTokenGenerator
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def generate_bedrock_token():
    try:
        token_generator = BedrockTokenGenerator()
        
        # Get credentials from default credential chain
        session = boto3.Session()
        credentials = session.get_credentials()
        
        if not credentials:
            raise NoCredentialsError()
        
        token = token_generator.generate_token(credentials, "us-west-2")
        
        print(f"Successfully generated token: {token[:30]}...")
        return token
        
    except NoCredentialsError:
        print("Error: No AWS credentials found")
    except ClientError as e:
        print(f"AWS service error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    generate_bedrock_token()
```

### Integration with AWS Bedrock Client

```python
import boto3
from aws_bedrock_token_generator import BedrockTokenGenerator

# Generate token
token_generator = BedrockTokenGenerator()
session = boto3.Session()
credentials = session.get_credentials()
bearer_token = token_generator.generate_token(credentials, "us-west-2")

# Use with Bedrock client (conceptual - actual implementation may vary)
bedrock_client = boto3.client('bedrock', region_name='us-west-2')
# Note: Token usage with Bedrock client depends on specific API requirements
```

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
