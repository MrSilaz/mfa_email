<?php
declare(strict_types=1);

return [


    'backend:inviteadmin' => [
//        'vendor' => 'typo3_console',
        'class' => \Ralffreit\MfaEmail\Command\InviteBackendAdminUserCommand::class,
    ],

];
