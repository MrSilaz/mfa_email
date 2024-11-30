<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'E-Mail MFA Provider',
    'description' => 'Provides a multi-factor authentication via E-Mail for TYPO3',
    'category' => 'be',
    'author' => 'Ralf Freit',
    'author_email' => 'ralf@freit.de',
    'state' => 'stable',
    'clearCacheOnLoad' => true,
    'version' => '2.0.0',
    'constraints' => [
        'depends' => [
            'typo3' => '13.4.0-13.4.99',
        ],
        'conflicts' => [
        ],
        'suggests' => [
        ],
    ],
    'autoload' => [
        'psr-4' => [
            'Ralffreit\\MfaEmail\\' => 'Classes/',
        ],
    ],
];
