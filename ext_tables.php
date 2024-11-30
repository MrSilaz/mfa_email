<?php
declare(strict_types=1);

defined('TYPO3') or die();

(function (): void {
    $GLOBALS['TYPO3_CONF_VARS']['MAIL']['layoutRootPaths'][805] = 'EXT:mfa_email/Resources/Private/Layout/Email/';
    $GLOBALS['TYPO3_CONF_VARS']['MAIL']['templateRootPaths'][805] = 'EXT:mfa_email/Resources/Private/Templates/Email/';
})();