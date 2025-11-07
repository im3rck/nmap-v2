# Contributing to ApexScan

Thank you for your interest in contributing to ApexScan! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Git
- Linux system (for full functionality)
- Root/sudo access (for raw socket operations)

### Setting Up Development Environment

1. Clone the repository:
```bash
git clone https://github.com/yourusername/apexscan.git
cd apexscan
```

2. Build the project:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

4. Check system requirements:
```bash
cargo run --bin apexscan -- check-system
```

## Development Workflow

### Branch Naming

- Feature branches: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`

### Commit Messages

Follow conventional commit format:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `perf`: Performance improvements
- `chore`: Build process or auxiliary tool changes

Example:
```
feat(scanner): add TCP NULL scan support

Implements TCP NULL scan (-sN) with proper state tracking
and result interpretation per RFC 793.

Closes #42
```

### Code Style

- Follow Rust standard formatting: `cargo fmt`
- Run clippy: `cargo clippy --all-targets --all-features`
- Document public APIs with doc comments
- Add unit tests for new functionality
- Keep functions focused and modular

### Testing

- Write unit tests for all new code
- Add integration tests for major features
- Ensure tests pass: `cargo test --all`
- Check code coverage: `cargo tarpaulin`

## Areas for Contribution

### Core Engine

- Protocol implementations (TCP, UDP, ICMP, ARP)
- Scan type implementations
- OS fingerprinting signatures
- Service detection probes

### Scripting Engine

- NSE script porting
- New security check scripts
- Script categories and organization

### Documentation

- User guides
- API documentation
- Example code
- Tutorials

### Testing

- Unit tests
- Integration tests
- Fuzzing harnesses
- Performance benchmarks

### UI/UX

- Web interface improvements
- CLI enhancements
- Visualization features

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write/update tests
5. Update documentation
6. Run `cargo fmt` and `cargo clippy`
7. Commit with descriptive message
8. Push to your fork
9. Create a Pull Request

### Pull Request Guidelines

- Provide clear description of changes
- Reference related issues
- Include test results
- Update CHANGELOG.md
- Ensure CI passes
- Request review from maintainers

## Code Review Process

1. Automated checks run on PR
2. Maintainer reviews code
3. Address feedback
4. Approval and merge

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email security concerns to: security@apexscan.io

### Security Guidelines

- Never commit credentials or secrets
- Validate all user input
- Follow secure coding practices
- Use safe Rust patterns
- Avoid unsafe code unless necessary (document why)

## Performance Guidelines

- Profile before optimizing
- Document performance-critical code
- Include benchmarks for hot paths
- Consider memory usage
- Optimize for common cases

## Documentation

### Code Documentation

```rust
/// Brief description of function
///
/// Longer description with details about behavior,
/// edge cases, and usage examples.
///
/// # Arguments
///
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// When this function returns errors
///
/// # Examples
///
/// ```
/// use apexscan::example;
/// let result = example(42);
/// ```
pub fn example(param: i32) -> Result<String> {
    // Implementation
}
```

### User Documentation

- Write in clear, concise language
- Include examples
- Explain "why" not just "what"
- Keep up to date with code changes

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Assume good intentions
- Focus on constructive feedback
- No harassment or discrimination

### Communication Channels

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and ideas
- Discord: Real-time chat (coming soon)
- Mailing List: Announcements (coming soon)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (TBD).

## Questions?

Feel free to:
- Open a GitHub Discussion
- Ask in issues with "question" label
- Email: dev@apexscan.io

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to ApexScan!
