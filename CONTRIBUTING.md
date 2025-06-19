# Contributing to AWS Bedrock Bearer Token Library

We welcome contributions! This document provides guidelines for contributing.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).

## How to Contribute

### Reporting Bugs
- Check existing issues first
- Include clear description and reproduction steps
- Provide environment details

### Pull Requests
1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Development Setup

```bash
# Clone and setup
git clone https://github.com/aws/aws-bedrock-bearer-token-python.git
cd aws-bedrock-bearer-token-python

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest tests/
```

## Code Style
- Follow PEP 8
- Use 4 spaces for indentation
- Line length: 88 characters
- Include docstrings

## License
By contributing, you agree that your contributions will be licensed under Apache License 2.0.
