# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/) or directly via email to aws-security@amazon.com. Please do **not** create a public GitHub issue.

If you package or distribute this software, or use this software in your applications, and you discover a potential security issue, please use the same process above.

## Security Best Practices

When using this library:

1. **Credential Management**: Never hardcode AWS credentials in your code. Use IAM roles, environment variables, or AWS credential files.

2. **Token Handling**: 
   - Bearer tokens are valid for 12 hours by default
   - Do not log or store bearer tokens
   - Transmit tokens only over HTTPS

3. **Network Security**: Always use HTTPS when making API calls with bearer tokens.

4. **Access Control**: Follow the principle of least privilege when configuring IAM permissions.

## Security Features

This library implements several security measures:

- **Stateless Design**: No credential storage or caching
- **SigV4 Signing**: Uses AWS Signature Version 4 for secure request signing
- **Time-Limited Tokens**: Generated tokens have a limited validity period
- **No Sensitive Data Logging**: The library does not log credentials or tokens

## Dependencies

This library has minimal dependencies to reduce the attack surface:
- `boto3` and `botocore` for AWS SDK functionality

We regularly monitor our dependencies for security vulnerabilities and update them as needed.
