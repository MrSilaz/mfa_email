<?php

declare(strict_types=1);

namespace Ralffreit\MfaEmail\Mfa;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Mime\Address;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderInterface;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderPropertyManager;
use TYPO3\CMS\Core\Authentication\Mfa\MfaViewType;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Http\ResponseFactory;
use TYPO3\CMS\Core\Mail\FluidEmail;
use TYPO3\CMS\Core\Mail\Mailer;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\View\ViewFactoryData;
use TYPO3\CMS\Core\View\ViewFactoryInterface;
use TYPO3\CMS\Core\View\ViewInterface;
use TYPO3\CMS\Extbase\Utility\LocalizationUtility;

class MailProvider implements MfaProviderInterface
{
    protected array $extensionConfiguration;

    protected ServerRequestInterface $request;

    public function __construct(
        protected Context              $context,
        protected ResponseFactory      $responseFactory,
        protected ViewFactoryInterface $viewFactory,
        ExtensionConfiguration         $extensionConfiguration
    )
    {
        $this->extensionConfiguration = $extensionConfiguration->get('mfa_email');
    }

    public function canProcess(ServerRequestInterface $request): bool
    {
        // @Todo: Check why not?
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
        ServerRequestInterface     $request,
        MfaProviderPropertyManager $propertyManager,
        MfaViewType                $type
    ): ResponseInterface
    {
        $this->request = $request;
        $viewFactoryData = new ViewFactoryData(
            templateRootPaths: ['EXT:mfa_email/Resources/Private/Templates/Mfa'],
            request: $request,
        );
        $view = $this->viewFactory->create($viewFactoryData);
        $view->assign('providerIdentifier', $propertyManager->getIdentifier());

        switch ($type) {
            case MfaViewType::SETUP:
            case MfaViewType::EDIT:
                $output = $this->prepareEditView($view, $propertyManager);
                break;
            case MfaViewType::AUTH:
                $output = $this->prepareAuthView($request, $view, $propertyManager);
                break;
        }
        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($output ?? '');

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

        if ($authCodeInput !== $properties['authCode']) {
            $properties['attempts'] = (isset($properties['attempts']) && (int)$properties['attempts'] ? (int)$properties['attempts'] : 0);
            $properties['attempts']++;
            $propertyManager->updateProperties($properties);
            return false;
        }

        $properties['authCode'] = '';
        $properties['attempts'] = 0;
        $properties['lastUsed'] = $this->context->getPropertyFromAspect('date', 'timestamp');

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

        $email = trim($request->getParsedBody()['email']);
        if (!$this->checkValidEmail($email)) {
            return false;
        }

        $properties = [
            'email' => $email,
            'active' => true
        ];
        return $propertyManager->hasProviderEntry()
            ? $propertyManager->updateProperties($properties)
            : $propertyManager->createProviderEntry($properties);
    }

    /**
     * Set auth code to the properties and send the E-Mail to the user
     */
    protected function sendAuthCodeEmail(MfaProviderPropertyManager $propertyManager, bool $resend = false): void
    {
        $newAuthCode = false;
        $authCode = $propertyManager->getProperty('authCode');
        if (empty($authCode)) {
            $authCode = $this->generateAuthCode();
            $propertyManager->updateProperties(['authCode' => $authCode]);
            $newAuthCode = true;
        }

        if ($newAuthCode || $resend) {
            $mailLayoutName = (isset($this->extensionConfiguration['mailLayoutName']) && trim($this->extensionConfiguration['mailLayoutName']) !== '') ? $this->extensionConfiguration['mailLayoutName'] : 'MfaEmail';
            $mailTemplateName = (isset($this->extensionConfiguration['mailTemplateName']) && trim($this->extensionConfiguration['mailTemplateName']) !== '') ? $this->extensionConfiguration['mailTemplateName'] : 'MfaEmail';

            $email = GeneralUtility::makeInstance(FluidEmail::class);
            $email->setRequest($this->request);
            $email
                ->to($propertyManager->getProperty('email'))
                ->setTemplate($mailTemplateName)
                ->assignMultiple([
                    'authCode' => $authCode,
                    'email' => $propertyManager->getProperty('email'),
                    'layoutName' => $mailLayoutName
                ]);

            $email->getHtmlBody(true); // Generate Subject
            $email->subject($email->getSubject());

            if (!empty($this->extensionConfiguration['mailSenderEmail'])) {
                $email->from(new Address($this->extensionConfiguration['mailSenderEmail'], $this->extensionConfiguration['mailSenderName']));
            }

            GeneralUtility::makeInstance(Mailer::class)->send($email);
        }
    }

    /**
     * Set the template and assign necessary variables for the edit view
     */
    protected function prepareEditView(ViewInterface $view, MfaProviderPropertyManager $propertyManager): string
    {
        $view->assignMultiple([
            'email' => (empty($propertyManager->getProperty('email')) ? $GLOBALS['BE_USER']->user['email'] : $propertyManager->getProperty('email')),
            'lastUsed' => $this->getDateTime($propertyManager->getProperty('lastUsed', 0)),
            'updated' => $this->getDateTime($propertyManager->getProperty('updated', 0)),
        ]);

        return $view->render('Edit');
    }

    /**
     * Set the template and assign necessary variables for the auth view
     */
    protected function prepareAuthView(ServerRequestInterface $request, ViewInterface $view, MfaProviderPropertyManager $propertyManager): string
    {
        $queryParams = $request->getQueryParams();
        $resend = !empty($queryParams['resend']) && $queryParams['resend'] === '1';

        $this->sendAuthCodeEmail($propertyManager, $resend);
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
        if (empty($email)) {
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

    public function isEmailValid($email)
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }


    /**
     * Helper to display localized flash messages
     */
    protected function showLocalizedFlashMessage(string $messageKey): void
    {
        $errorMessage = GeneralUtility::makeInstance(
            FlashMessage::class,
            $this->showLocalizedMessage($messageKey . '.message'),
            $this->showLocalizedMessage($messageKey . '.title'),
            ContextualFeedbackSeverity::ERROR,
            true
        );
        $flashMessageService = GeneralUtility::makeInstance(FlashMessageService::class);
        $messageQueue = $flashMessageService->getMessageQueueByIdentifier();
        $messageQueue->addMessage($errorMessage);
    }

    /**
     * Helper to display localized flash messages
     */
    protected function showLocalizedMessage(string $messageKey, array $params = []): string
    {
        return LocalizationUtility::translate($messageKey, 'mfa_email', $params);
    }

    /**
     * Set maximum attempts or -1 to deactivate
     */
    protected function getMaxAttempts(): int
    {
        $maxAttempts = (isset($this->extensionConfiguration['maxAttempts']) ? (int)$this->extensionConfiguration['maxAttempts'] : 9999999);
        return ($maxAttempts !== -1 ? $maxAttempts : 9999999);
    }
}
