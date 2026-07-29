<?php

declare(strict_types=1);

namespace Ralffreit\MfaEmail\Mfa;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Mime\Address;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderInterface;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderPropertyManager;
use TYPO3\CMS\Core\Authentication\Mfa\MfaViewType;
use TYPO3\CMS\Core\Configuration\Exception\ExtensionConfigurationExtensionNotConfiguredException;
use TYPO3\CMS\Core\Configuration\Exception\ExtensionConfigurationPathDoesNotExistException;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Http\ResponseFactory;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Mail\MailerInterface;
use TYPO3\CMS\Core\Mail\TemplatedEmailFactory;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Core\Utility\MathUtility;
use TYPO3\CMS\Core\View\ViewFactoryData;
use TYPO3\CMS\Core\View\ViewFactoryInterface;
use TYPO3\CMS\Core\View\ViewInterface;

class MailProvider implements MfaProviderInterface
{
    /**
     * Used whenever "maxAttempts" is missing or not a valid integer. Must never
     * fall back to "unlimited": a six digit code is trivially brute forced.
     */
    protected const DEFAULT_MAX_ATTEMPTS = 6;

    /**
     * Lifetime of a generated authentication code in seconds.
     */
    protected const DEFAULT_CODE_VALIDITY_PERIOD = 900;

    protected const LANGUAGE_FILE = 'LLL:EXT:mfa_email/Resources/Private/Language/locallang.xlf:';

    protected array $extensionConfiguration;

    protected ?ServerRequestInterface $request = null;

    public function __construct(
        protected readonly Context $context,
        protected readonly ResponseFactory $responseFactory,
        protected readonly ViewFactoryInterface $viewFactory,
        protected readonly TemplatedEmailFactory $templatedEmailFactory,
        protected readonly MailerInterface $mailer,
        protected readonly FlashMessageService $flashMessageService,
        protected readonly LanguageServiceFactory $languageServiceFactory,
        ExtensionConfiguration $extensionConfiguration,
    ) {
        try {
            $this->extensionConfiguration = $extensionConfiguration->get('mfa_email');
        } catch (ExtensionConfigurationExtensionNotConfiguredException|ExtensionConfigurationPathDoesNotExistException) {
            // Not configured yet - the getters below fall back to safe defaults.
            $this->extensionConfiguration = [];
        }
    }

    public function canProcess(ServerRequestInterface $request): bool
    {
        // Sending a code by e-mail has no further technical requirements.
        return true;
    }

    /**
     * Evaluate if the provider is activated
     */
    public function isActive(MfaProviderPropertyManager $propertyManager): bool
    {
        return (bool)$propertyManager->getProperty('active');
    }

    /**
     * Evaluate if the provider is temporarily locked
     */
    public function isLocked(MfaProviderPropertyManager $propertyManager): bool
    {
        $attempts = (int)$propertyManager->getProperty('attempts', 0);

        // Assume the provider is locked in case the maximum attempts are exceeded.
        // A provider however can only be locked if set up - an entry exists in database.
        return $propertyManager->hasProviderEntry() && $attempts >= $this->getMaxAttempts();
    }

    /**
     * Initialize view and forward to the appropriate implementation
     */
    public function handleRequest(
        ServerRequestInterface $request,
        MfaProviderPropertyManager $propertyManager,
        MfaViewType $type
    ): ResponseInterface {
        $this->request = $request;

        $view = $this->viewFactory->create(new ViewFactoryData(
            templateRootPaths: ['EXT:mfa_email/Resources/Private/Templates/Mfa'],
            request: $request,
        ));
        $view->assign('providerIdentifier', $propertyManager->getIdentifier());

        $output = match ($type) {
            MfaViewType::SETUP, MfaViewType::EDIT => $this->prepareEditView($view, $propertyManager),
            MfaViewType::AUTH => $this->prepareAuthView($request, $view, $propertyManager),
        };

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($output);

        return $response;
    }

    /**
     * Verify the given auth code
     */
    public function verify(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        if (!$this->isActive($propertyManager) || $this->isLocked($propertyManager)) {
            // Can not verify an inactive or locked provider
            return false;
        }

        $authCodeInput = trim((string)($request->getQueryParams()['authCode'] ?? $request->getParsedBody()['authCode'] ?? ''));
        $properties = $propertyManager->getProperties();
        $storedAuthCode = (string)($properties['authCode'] ?? '');

        // Never compare against an empty code. A forged empty submission - or an empty
        // stored code - would otherwise pass and bypass MFA (TYPO3-EXT-SA-2026-007).
        if ($authCodeInput === '' || $storedAuthCode === '') {
            return false;
        }

        // Discard an expired code rather than comparing it, so it cannot be replayed later.
        if ($this->isAuthCodeExpired($properties)) {
            $propertyManager->updateProperties([
                'authCode' => '',
                'authCodeCreated' => 0,
            ]);
            return false;
        }

        // Timing safe comparison so the stored code cannot be recovered by measuring
        // how long the comparison takes.
        if (!hash_equals($storedAuthCode, $authCodeInput)) {
            if (!isset($properties['attempts']) || !MathUtility::canBeInterpretedAsInteger($properties['attempts'])) {
                $properties['attempts'] = 0;
            }
            $properties['attempts']++;
            if ($properties['attempts'] >= $this->getMaxAttempts()) {
                // Reset the code, so it cannot be forged once the provider is unlocked again.
                $properties['authCode'] = '';
                $properties['authCodeCreated'] = 0;
            }
            $propertyManager->updateProperties($properties);
            return false;
        }

        // Invalidate the code right after a successful login to prevent replay attacks.
        $properties['authCode'] = '';
        $properties['authCodeCreated'] = 0;
        $properties['attempts'] = 0;
        $properties['lastUsed'] = $this->getTimestamp();

        return $propertyManager->updateProperties($properties);
    }

    /**
     * Activate the provider
     */
    public function activate(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        return $this->update($request, $propertyManager);
    }

    /**
     * Handle the unlock action by resetting the attempts provider property
     */
    public function unlock(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        if (!$this->isActive($propertyManager) || !$this->isLocked($propertyManager)) {
            return false;
        }
        return $propertyManager->updateProperties(['attempts' => 0]);
    }

    /**
     * Handle the deactivate action
     */
    public function deactivate(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        if (!$this->isActive($propertyManager)) {
            return false;
        }
        return $propertyManager->updateProperties(['active' => false]);
    }

    /**
     * Update the provider data
     */
    public function update(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        if (!$this->canProcess($request)) {
            return false;
        }

        $parsedBody = $request->getParsedBody();
        $email = trim((string)(is_array($parsedBody) ? ($parsedBody['email'] ?? '') : ''));
        if (!$this->checkValidEmail($email)) {
            return false;
        }

        $properties = [
            'attempts' => 0,
            'authCode' => '',
            'authCodeCreated' => 0,
            'email' => $email,
            'active' => true,
        ];

        return $propertyManager->hasProviderEntry()
            ? $propertyManager->updateProperties($properties)
            : $propertyManager->createProviderEntry($properties);
    }

    /**
     * Set auth code to the properties and send the E-Mail to the user
     */
    protected function sendAuthCodeEmail(MfaProviderPropertyManager $propertyManager): void
    {
        $authCode = (string)$propertyManager->getProperty('authCode', '');

        if ($authCode === '' || $this->isAuthCodeExpired($propertyManager->getProperties())) {
            $authCode = $this->generateAuthCode();
            $propertyManager->updateProperties([
                'authCode' => $authCode,
                'authCodeCreated' => $this->getTimestamp(),
            ]);
        }

        $recipient = (string)$propertyManager->getProperty('email', '');
        if ($recipient === '') {
            return;
        }

        $email = $this->templatedEmailFactory->create($this->request);
        $email
            ->to($recipient)
            ->setTemplate($this->getTemplateName('mailTemplateName'))
            ->assignMultiple([
                'authCode' => $authCode,
                'email' => $recipient,
                'layoutName' => $this->getTemplateName('mailLayoutName'),
            ]);

        // The subject is rendered by the template, so the body has to be generated first.
        $email->getHtmlBody(true);
        $email->subject($email->getSubject());

        $senderEmail = trim((string)($this->extensionConfiguration['mailSenderEmail'] ?? ''));
        if ($senderEmail !== '') {
            $senderName = trim((string)($this->extensionConfiguration['mailSenderName'] ?? ''));
            $email->from(new Address($senderEmail, $senderName));
        }

        $this->mailer->send($email);
    }

    /**
     * Set the template and assign necessary variables for the edit view
     */
    protected function prepareEditView(ViewInterface $view, MfaProviderPropertyManager $propertyManager): string
    {
        $email = (string)$propertyManager->getProperty('email', '');
        if ($email === '') {
            $email = (string)($GLOBALS['BE_USER']->user['email'] ?? '');
        }

        $view->assignMultiple([
            'email' => $email,
            'lastUsed' => $this->getDateTime((int)$propertyManager->getProperty('lastUsed', 0)),
            'updated' => $this->getDateTime((int)$propertyManager->getProperty('updated', 0)),
        ]);

        return $view->render('Edit');
    }

    /**
     * Set the template and assign necessary variables for the auth view
     */
    protected function prepareAuthView(ServerRequestInterface $request, ViewInterface $view, MfaProviderPropertyManager $propertyManager): string
    {
        $queryParams = $request->getQueryParams();

        $this->sendAuthCodeEmail($propertyManager);
        $view->assignMultiple([
            'isLocked' => $this->isLocked($propertyManager),
            'resendLink' => '?' . http_build_query(array_merge($queryParams, ['resend' => '1'])),
        ]);

        return $view->render('Auth');
    }

    /**
     * Generates a random authentication code with 6 digits
     */
    protected function generateAuthCode(): string
    {
        return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Evaluate if the stored authentication code has outlived its validity period
     */
    protected function isAuthCodeExpired(array $properties): bool
    {
        $validityPeriod = $this->getCodeValidityPeriod();
        if ($validityPeriod <= 0) {
            // Expiry explicitly disabled by configuration.
            return false;
        }

        $created = (int)($properties['authCodeCreated'] ?? 0);
        if ($created <= 0) {
            // Codes stored before this extension tracked a creation time carry no
            // timestamp. Treat them as expired so they get replaced by a fresh one.
            return true;
        }

        return ($this->getTimestamp() - $created) > $validityPeriod;
    }

    /**
     * Current time, taken from the context so it stays consistent within one request
     */
    protected function getTimestamp(): int
    {
        return (int)$this->context->getPropertyFromAspect('date', 'timestamp');
    }

    /**
     * Return the timestamp as local time (date string) by applying the globally configured format
     */
    protected function getDateTime(int $timestamp): string
    {
        if ($timestamp === 0) {
            return '';
        }

        return date(
            $GLOBALS['TYPO3_CONF_VARS']['SYS']['ddmmyy'] . ' ' . $GLOBALS['TYPO3_CONF_VARS']['SYS']['hhmm'],
            $timestamp
        ) ?: '';
    }

    protected function checkValidEmail(string $email): bool
    {
        $messageKey = null;
        if ($email === '') {
            $messageKey = 'error.email.empty';
        } elseif (!$this->isEmailValid($email)) {
            $messageKey = 'error.email.notvalid';
        }

        if ($messageKey !== null) {
            $this->showLocalizedFlashMessage($messageKey);
            return false;
        }

        return true;
    }

    public function isEmailValid(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Resolve a configured Fluid template/layout name, falling back to the shipped default
     */
    protected function getTemplateName(string $key, string $default = 'MfaEmail'): string
    {
        $name = trim((string)($this->extensionConfiguration[$key] ?? ''));

        return $name !== '' ? $name : $default;
    }

    /**
     * Helper to display localized flash messages
     */
    protected function showLocalizedFlashMessage(string $messageKey): void
    {
        $flashMessage = new FlashMessage(
            $this->translate($messageKey . '.message'),
            $this->translate($messageKey . '.title'),
            ContextualFeedbackSeverity::ERROR,
            true
        );

        $this->flashMessageService->getMessageQueueByIdentifier()->addMessage($flashMessage);
    }

    /**
     * Helper to translate a label in the backend user's language
     */
    protected function translate(string $messageKey): string
    {
        return $this->languageServiceFactory
            ->createForBackendUser()
            ->sL(self::LANGUAGE_FILE . $messageKey);
    }

    /**
     * Maximum failed attempts before the provider locks. "-1" disables locking.
     */
    protected function getMaxAttempts(): int
    {
        if (!isset($this->extensionConfiguration['maxAttempts'])
            || !MathUtility::canBeInterpretedAsInteger($this->extensionConfiguration['maxAttempts'])
        ) {
            return self::DEFAULT_MAX_ATTEMPTS;
        }

        $maxAttempts = (int)$this->extensionConfiguration['maxAttempts'];
        if ($maxAttempts === -1) {
            // Locking explicitly disabled.
            return PHP_INT_MAX;
        }

        // Any other non positive value is a misconfiguration and must not disable locking.
        return $maxAttempts > 0 ? $maxAttempts : self::DEFAULT_MAX_ATTEMPTS;
    }

    /**
     * Lifetime of an authentication code in seconds. "0" means the code never expires.
     */
    protected function getCodeValidityPeriod(): int
    {
        if (!isset($this->extensionConfiguration['codeValidityPeriod'])
            || !MathUtility::canBeInterpretedAsInteger($this->extensionConfiguration['codeValidityPeriod'])
        ) {
            return self::DEFAULT_CODE_VALIDITY_PERIOD;
        }

        $validityPeriod = (int)$this->extensionConfiguration['codeValidityPeriod'];

        // "-1" (or any other non positive value) disables the expiry.
        return $validityPeriod > 0 ? $validityPeriod : 0;
    }
}
