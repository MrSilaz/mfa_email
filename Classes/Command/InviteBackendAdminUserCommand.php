<?php
declare(strict_types=1);
namespace Ralffreit\MfaEmail\Command;

/*
 * This file is part of the TYPO3 Console project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read
 * LICENSE file that was distributed with this source code.
 *
 */

use Helhum\Typo3Console\Exception\ArgumentValidationFailedException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Mime\Address;
use TYPO3\CMS\Core\Authentication\Mfa\MfaProviderPropertyManager;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Restriction\EndTimeRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\HiddenRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\StartTimeRestriction;
use TYPO3\CMS\Core\Mail\FluidEmail;
use TYPO3\CMS\Core\Mail\Mailer;
use TYPO3\CMS\Core\Site\SiteFinder;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class InviteBackendAdminUserCommand extends Command
{
    private $passwordAsArgument = true;

    protected function configure()
    {
        $this->setDescription('Invite admin backend user');
        $this->setHelp('Invite a new user with administrative access & mta email anable.');
        $this->setDefinition(
            [
                new InputArgument(
                    'username',
                    InputArgument::REQUIRED,
                    'Username of the user'
                ),
                new InputArgument(
                    'email',
                    InputArgument::REQUIRED,
                    'email of the user'
                ),
            ]
        );
    }

    protected function interact(InputInterface $input, OutputInterface $output)
    {
        $io = new SymfonyStyle($input, $output);
        if (empty($input->getArgument('username'))) {
            $username = $io->ask(
                'Username',
                null,
                function ($username) {
                    if ($error = $this->validateUsername($username)) {
                        throw new ArgumentValidationFailedException($error);
                    }

                    return $username;
                }
            );
            $input->setArgument('username', $username);
        }
        if (empty($input->getArgument('email'))) {
            $email = $io->ask(
                'email',
                function ($email) {
                    if ($error = $this->validateEmail($email)) {
                        throw new ArgumentValidationFailedException($error);
                    }

                    return $email;
                }
            );
            $this->passwordAsArgument = false;
            $input->setArgument('email', $email);
        }
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $username = $input->getArgument('username');
        $email = $input->getArgument('email');
//        if ($this->passwordAsArgument) {
//            $output->writeln('<warning>Using a password on the command line interface can be insecure.</warning>');
//        }
        if ($userError = $this->validateUsername($username)) {
            $output->writeln(sprintf('<error>%s</error>', $userError));
        }
        if ($emailError = $this->validateEmail($email)) {
            $output->writeln(sprintf('<error>%s</error>', $emailError));
        }
        if (isset($userError) || isset($emailError)) {
            return 1;
        }
        $passwordHasher = GeneralUtility::makeInstance(PasswordHashFactory::class)->getDefaultHashInstance('BE');
        $password = bin2hex(random_bytes(8));
        $adminUserFields = [
            'username' => $username,
            'password' => $passwordHasher->getHashedPassword($password),
            'email' => $email,
            'mfa' => '{"email":{"email":"'.$email.',"active":true,"created":'.$GLOBALS['EXEC_TIME'].',"updated":'.$GLOBALS['EXEC_TIME'].'}}',
            'admin' => 1,
            'tstamp' => $GLOBALS['EXEC_TIME'],
            'crdate' => $GLOBALS['EXEC_TIME'],
        ];
        $connectionPool = GeneralUtility::makeInstance(ConnectionPool::class);
        $connectionPool->getConnectionForTable('be_users')
            ->insert('be_users', $adminUserFields);
            $adminUserFields['passwordText'] = $password;
        $siteFinder = GeneralUtility::makeInstance(SiteFinder::class);
        $sites = $siteFinder->getAllSites();
                $adminUserFields['PublicPath'] =  array_pop($sites)->getBase();
            $emailMsg = GeneralUtility::makeInstance(FluidEmail::class);
            $emailMsg
                ->to($email)
                ->setTemplate('InviteEmail')
                ->assignMultiple($adminUserFields)
                ->assign('passwordText', $password);

            $emailMsg->getHtmlBody(true); // Generate Subject
            $emailMsg->subject('Invitation as typo3 backend user');

            if (!empty($this->extensionConfiguration['mailSenderEmail'])) {
                $emailMsg->from(new Address($this->extensionConfiguration['mailSenderEmail'], $this->extensionConfiguration['mailSenderName']));
            }

            GeneralUtility::makeInstance(Mailer::class)->send($emailMsg);

        $output->writeln(sprintf('<info>Created admin user with username "%s".</info>', $username));

        return 0;
    }

    private function validateUsername(?string $username): ?string
    {
        if (empty($username)) {
            return 'Username must not be empty.';
        }
        $cleanedUsername = strtolower(preg_replace('/\\s/i', '', $username));
        if ($username !== $cleanedUsername) {
            return sprintf('No special characters are allowed in username. Use "%s" as username instead.', $cleanedUsername);
        }
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('be_users');
        $queryBuilder->getRestrictions()
             ->removeByType(StartTimeRestriction::class)
             ->removeByType(EndTimeRestriction::class)
             ->removeByType(HiddenRestriction::class);
        $userExists = $queryBuilder->count('uid')
            ->from('be_users')
            ->where(
                $queryBuilder->expr()->eq('username', $queryBuilder->createNamedParameter($username))
            )->execute()->fetchColumn() > 0;

        if ($userExists) {
            return sprintf('A user with username "%s" already exists.', $username);
        }

        return null;
    }

    private function validateEmail(?string $email): ?string
    {
        if (empty($email)) {
            return 'email must not be empty.';
        }
        if (strpos($email, '?') > 0) {
            return 'Must be an email address.';
        }
        if(!GeneralUtility::validEmail($email)){
            return 'Must be an email address.';
        }
        return null;
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
}
