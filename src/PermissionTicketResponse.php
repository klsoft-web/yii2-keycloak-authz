<?php

namespace Klsoft\Yii2KeycloakAuthz;

final class PermissionTicketResponse
{
    public function __construct(
        private string $realm,
        private string $asUri,
        private string $ticket)
    {
    }

    public function realm(): string
    {
        return $this->realm;
    }

    public function asUri(): string
    {
        return $this->asUri;
    }

    public function ticket(): string
    {
        return $this->ticket;
    }
}
