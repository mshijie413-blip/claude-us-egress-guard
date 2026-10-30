# Security Policy

## Reporting

Open a private security advisory in the GitHub repository. Do not include live
credentials, customer records, private keys, packet captures or personal data
in an issue.

## Repository Hygiene

- Real Xray client/server configurations stay outside this repository.
- Generated PAC files contain routing rules only, never credentials.
- LaunchAgent and LaunchDaemon examples use placeholder paths.
- Run `python3 scripts/check_public_safety.py .` before every commit.
- Rotate any credential that was ever committed, even if the commit was later
  removed from the visible branch.

## Deployment Warning

This project changes privileged macOS networking only when an operator installs
the provided examples. The examples are intentionally not a one-click root
installer. Test in a separate macOS account or disposable host before using the
design on a primary workstation.
