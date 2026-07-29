# TYPO3 Extension ``mfa_email``

This extension adds the E-Mail MFA provider to TYPO3.

## Compatibility

| Extension version | TYPO3               | PHP         |
|-------------------|---------------------|-------------|
| 3.x               | 14.3 LTS            | 8.2 - 8.5   |
| 2.x               | 13.4 LTS            | 8.2+        |
| 1.x               | 11.5 LTS & 12.4 LTS | 7.4+ & 8.1+ |

## Installation

You can install the extension via composer

```composer require ralffreit/mfa-email```

or via [TYPO3 extension repository](https://extensions.typo3.org/extension/mfa_email/)

## About Mail MFA

With the mail-based authentication code, you can increase the security of your accounts by requesting a six-digit code every time you log in. Our system sends an email with a secret code to your email address.

Each authentication code is valid only once and expires after a configurable validity period (15 minutes by default).

Setting up:
1. Enter your email address.
2. Please check your email address twice.
3. Submit the form to activate the MFA email provider.

## Available languages

- German
- English
