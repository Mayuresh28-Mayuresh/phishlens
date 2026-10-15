# Contributing

Thanks for helping improve PhishLens. Keep changes defensive, privacy-conscious, and explainable.

1. Open an issue describing the problem or proposed change.
2. Do not submit real phishing samples containing personal data, live credentials, or confidential messages. Use sanitized synthetic examples.
3. Add unit tests for new heuristics and provider behavior.
4. Do not add automatic link-opening, attachment execution, credential collection, or stealth behavior.
5. Run `python -m unittest discover -s tests -v` before submitting a pull request.
6. Keep API keys, `.env` files, and private data out of commits.

By contributing, you agree that your contributions may be distributed under this project's MIT License.
