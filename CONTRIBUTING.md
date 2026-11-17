# Contributing

Thanks for helping. Bug reports, feed and data-source suggestions, documentation fixes and code are all welcome.

## Before you start

- **Bugs:** open an issue with the version, how you run it, what you expected and what happened.
- **Features:** open an issue first so we can agree on the approach before you spend time on code.
- **Security problems:** never in a public issue — see [SECURITY.md](SECURITY.md).

## Making a change

1. Fork, create a branch from `main`.
2. Set up a dev environment: [docs/developers/02_Development.md](docs/developers/02_Development.md).
3. Make the change, with tests. Keep the security invariants in
   [docs/developers/01_Architecture.md](docs/developers/01_Architecture.md#6-security-invariants-do-not-break-these).
4. Update the documentation the change touches (user guide, admin / developer docs) and add a line to `CHANGELOG.md`
   under *Unreleased*.
5. Run the release gate locally — it must pass:
   ```bash
   python -I tools/security_check.py
   ```
6. Open a pull request describing what changed and why. CI runs the same gate.

## Guidelines

- Small, focused pull requests are reviewed faster.
- No new runtime dependency without a good reason; every dependency is hash-pinned in `requirements.lock`.
- The front end has no build step: plain JavaScript, DOM built with `h()`, no inline scripts or styles.
- Sources must be read honestly: no user-agent spoofing, no bypassing bot checks, paywalls or logins, and respect for
  rate limits. Contributions that scrape around such protections will not be accepted.
- Be kind and constructive — see the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contribution is licensed under the
[GNU AGPL v3.0 or later](LICENSE), the license of this project.
