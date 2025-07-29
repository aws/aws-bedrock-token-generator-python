# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-10-25

### Added
- New `provide_token()` helper function as a simplified entry point for users
- Support for default AWS region from environment (`AWS_REGION`) if not explicitly provided
- Token expiry is now configurable via `expiry: timedelta`, with a default of 12 hours

## [1.0.0] - 2025-06-10

### Added
- Initial release of AWS Bedrock Token Generator for Python
- `BedrockTokenGenerator` class for generating bearer tokens
- Support for AWS SigV4 signing with 12-hour token expiration
- Integration with boto3 credential providers
- Comprehensive unit tests
- Type hints for better IDE support
- Documentation and examples

### Features
- Generate short-term bearer tokens for AWS Bedrock API authentication
- Multi-region support
- Support for various AWS credential providers
- Secure token generation using AWS SigV4 signing
- Base64-encoded token format with version information

### Security
- Tokens expire after 12 hours
- Uses AWS SigV4 signing for secure authentication
- No long-term credential exposure

## [Unreleased]

### Planned
- Additional credential provider examples
- Enhanced error handling
- Performance optimizations
