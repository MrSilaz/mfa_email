<?php

/*
 * Since TYPO3 v14.2 this file is no longer evaluated.
 * all metadata is read from composer.json (see "extra/typo3/cms").
 * It is only kept in sync for third party tooling such as the TYPO3 Extension Repository and Tailor
 */
$EM_CONF[$_EXTKEY] = [
    'title' => 'E-Mail MFA Provider',
    'description' => 'Provides a multi-factor authentication via E-Mail for TYPO3',
    'category' => 'be',
    'author' => 'Ralf Freit',
    'author_email' => 'ralf@freit.de',
    'state' => 'stable',
    'clearCacheOnLoad' => true,
    'version' => '3.0.0',
    'constraints' => [
        'depends' => [
            'typo3' => '14.3.0-14.3.99',
            'php' => '8.2.0-8.5.99',
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
