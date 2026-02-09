<?php

namespace Klsoft\Yii2KeycloakAuthz;

interface KeycloakRepositoryInterface
{
    /**
     * Get permission ticket.
     *
     * @param string $accessToken
     * @param array $permissions
     *
     * @return PermissionTicketResult
     */
    public function getPermissionTicket(string $accessToken, array $permissions): PermissionTicketResult;
}
