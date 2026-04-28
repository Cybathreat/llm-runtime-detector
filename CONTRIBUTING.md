# Contributing to LLM Runtime Detector

Thanks for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/llm-runtime-detector.git`
3. Install in editable mode: `pip install -e ".[dev]"`
4. Run tests: `pytest tests/`

## Development Workflow

- Create a feature branch: `git checkout -b feature/your-feature`
- Make your changes
- Run tests and ensure coverage stays above 80%
- Run linting: `black . && flake8 && mypy src/`
- Commit with a clear message
- Push and open a PR

## Code Standards

- Python 3.10+
- Type hints encouraged
- Docstrings for public APIs
- Tests for new features

## Reporting Issues

Please include:
- Python version
- Steps to reproduce
- Expected vs actual behavior
