# TYPO3 Extension ``mfa_mail``

This extension adds the E-Mail MFA provider to TYPO3, available for TYPO3 v11 ans TYPO3 v12.

## Installation

You can install the extension via composer 

```composer require ralffreit/mfa-email```

or via [TYPO3 extension repository](https://extensions.typo3.org/extension/mfa_email/)

## About Mail MFA

With the mail-based authentication code, you can increase the security of your accounts by requesting a six-digit code every time you log in. This our system sends an email with a secret code to your email address.

Each authentication code is valid only once.

Setting up:
1. Enter your email address.
2. Please check your email address twice.
3. Submit the form to activate the MFA email provider.

## Available languages

- German
- English
