<?php

$EM_CONF['mfa_email'] = [
    'title' => 'E-Mail MFA Provider',
    'description' => 'Provides a multi-factor authentication via E-Mail for TYPO3',
    'category' => 'be',
    'author' => 'Ralf Freit',
    'author_email' => 'ralf@freit.de',
    'state' => 'stable',
    'clearCacheOnLoad' => true,
    'version' => '1.0.0',
    'constraints' => [
        'depends' => [
            'typo3' => '11.5.0-12.2.99'
        ]
    ],
    'autoload' => [
        'psr-4' => [
            'Ralffreit\\MfaEmail\\' => "Classes/"
        ]
    ]
];