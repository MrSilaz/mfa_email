<?php

declare(strict_types=1);

/*
 * This file is part of the package web-tp3/mfa_email.
 *
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace Ralffreit\MfaEmail\Mfa;

use Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Mime\Address;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderInterface;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderPropertyManager;
use TYPO3\CMS\Core\Authentication\Mfa\MfaViewType;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Context\Exception\AspectNotFoundException;
use TYPO3\CMS\Core\Http\ResponseFactory;

use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Mail\FluidEmail;
use TYPO3\CMS\Core\Mail\Mailer;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;

use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Fluid\View\StandaloneView;

use TYPO3Fluid\Fluid\View\ViewInterface;

class MailProvider implements MfaProviderInterface
{
    protected Context $context;
    protected ResponseFactory $responseFactory;
    protected array $extensionConfiguration;

    protected ServerRequestInterface $request;

    /**
     * @param Context $context
     * @param ResponseFactory $responseFactory
     * @param ExtensionConfiguration $extensionConfiguration
     * @throws Exception
     */
    public function __construct(Context $context, ResponseFactory $responseFactory, ExtensionConfiguration $extensionConfiguration)
    {
        $this->context = $context;
        $this->responseFactory = $responseFactory;
        $this->extensionConfiguration = $extensionConfiguration->get('mfa_email');
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function canProcess(ServerRequestInterface $request): bool
    {
        // @Todo: Check why not?
        return true;
    }

    /**
     * Evaluate if the provider is activated
     *
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
     */
    public function isActive(MfaProviderPropertyManager $propertyManager): bool
    {
        return (bool)$propertyManager->getProperty('active');
    }

    /**
     * Evaluate if the provider is temporarily locked
     *
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
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
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @param string $type
     * @return ResponseInterface
     */
    public function handleRequest(
        ServerRequestInterface $request,
        MfaProviderPropertyManager $propertyManager,
        string $type
    ): ResponseInterface {
        $this->request = $request;
        $view = GeneralUtility::makeInstance(StandaloneView::class);
        $view->setTemplateRootPaths(['EXT:mfa_email/Resources/Private/Templates/Mfa']);
        switch ($type) {
            case MfaViewType::SETUP:
            case MfaViewType::EDIT:
                $this->prepareEditView($view, $propertyManager);
                break;
            case MfaViewType::AUTH:
                $this->prepareAuthView($request, $view, $propertyManager);
                break;
        }
        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($view->assign('providerIdentifier', $propertyManager->getIdentifier())->render());
        return $response;
    }

    /**
     * Verify the given auth code
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
     * @throws AspectNotFoundException
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
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
     */
    public function activate(ServerRequestInterface $request, MfaProviderPropertyManager $propertyManager): bool
    {
        return $this->update($request, $propertyManager);
    }

    /**
     * Handle the unlock action by resetting the attempts provider property
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
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
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
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
     *
     * @param ServerRequestInterface $request
     * @param MfaProviderPropertyManager $propertyManager
     * @return bool
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
     * @param MfaProviderPropertyManager $propertyManager
     * @param bool $resend
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
     *
     * @param ViewInterface $view
     * @param MfaProviderPropertyManager $propertyManager
     */
    protected function prepareEditView(ViewInterface $view, MfaProviderPropertyManager $propertyManager): void
    {
        $view->setTemplate('Edit');
        $view->assignMultiple([
            'email' => (empty($propertyManager->getProperty('email')) ? $GLOBALS['BE_USER']->user['email'] : $propertyManager->getProperty('email')),
            'lastUsed' => $this->getDateTime($propertyManager->getProperty('lastUsed', 0)),
            'updated' => $this->getDateTime($propertyManager->getProperty('updated', 0)),
        ]);
    }

    /**
     * Set the template and assign necessary variables for the auth view
     *
     * @param ServerRequestInterface $request
     * @param ViewInterface $view
     * @param MfaProviderPropertyManager $propertyManager
     */
    protected function prepareAuthView(ServerRequestInterface $request, ViewInterface $view, MfaProviderPropertyManager $propertyManager): void
    {
        $queryParams = $request->getQueryParams();
        $resend = !empty($queryParams['resend']) && $queryParams['resend'] === '1';

        $this->sendAuthCodeEmail($propertyManager, $resend);
        $view->setTemplate('Auth');
        $view->assignMultiple([
            'isLocked' => $this->isLocked($propertyManager),
            'resendLink' => '?' . http_build_query(array_merge($queryParams, ['resend' => '1'])),
        ]);
    }

    /**
     * Generates an random authentication code with 6 digits
     *
     * @return string
     */
    protected function generateAuthCode(): string
    {
        $code = [];
        $charSet = '0123456789';
        $charSetLength = strlen($charSet) - 1;
        for ($i = 0; $i < 6; $i++) {
            $n = rand(0, $charSetLength);
            $code[] = $charSet[$n];
        }
        shuffle($code);
        return implode($code);
    }

    /**
     * Return the timestamp as local time (date string) by applying the globally configured format
     *
     * @param int $timestamp
     * @return string
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

    protected function checkValidEmail(string $email):bool
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
     * @param string $messageKey
     */
    protected function showLocalizedFlashMessage(string $messageKey): void
    {
        $errorMessage = GeneralUtility::makeInstance(
            FlashMessage::class,
            $this->showLocalizedMessage($messageKey . '.message'),
            $this->showLocalizedMessage($messageKey . '.title'),
            FlashMessage::ERROR,
            true
        );
        $flashMessageService = GeneralUtility::makeInstance(FlashMessageService::class);
        $messageQueue = $flashMessageService->getMessageQueueByIdentifier();
        $messageQueue->addMessage($errorMessage);
    }

    /**
     * Helper to display localized flash messages
     * @param string $messageKey
     */
    protected function showLocalizedMessage(string $messageKey, array $params = []): string
    {
        return  \TYPO3\CMS\Extbase\Utility\LocalizationUtility::translate($messageKey, 'mfa_email', $params); // $this->getLanguageService()->sL($languageFilePrefix . $messageKey);
    }

    /**
     * Set maximum attempts or -1 to deactivate
     *
     * @return int
     */
    protected function getMaxAttempts(): int
    {
        $maxAttempts = (isset($this->extensionConfiguration['maxAttempts']) ? (int)$this->extensionConfiguration['maxAttempts'] :  9999999);
        $maxAttempts = ($maxAttempts !== -1 ? $maxAttempts: 9999999);

        return $maxAttempts;
    }

    /**
     * @return LanguageService
     */
    private function getLanguageService(): LanguageService
    {
        return $GLOBALS['LANG'];
    }
}
