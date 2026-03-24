# Contributing to SysGuard

Thank you for your interest in contributing!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/sysguard.git
cd sysguard

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Code Style

- Follow PEP 8 guidelines
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Add docstrings to new functions

## Testing

```bash
# Run basic tests
python -m pytest tests/

# Or test manually
python launcher.py
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Bug Reports

Use GitHub Issues to report bugs. Include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior

## Feature Requests

Open an issue with:
- Clear description
- Use case
- Any implementation ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
