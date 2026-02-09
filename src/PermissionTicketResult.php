<?php

namespace Klsoft\Yii2KeycloakAuthz;

final class PermissionTicketResult
{
    public function __construct(
        private ?PermissionTicketResponse $permissionTicketResponse,
        private int                       $responseStatusCode = 200,
        private array                     $errors = [])
    {
    }

    public function permissionTicketResponse(): ?PermissionTicketResponse
    {
        return $this->permissionTicketResponse;
    }

    public function responseStatusCode(): int
    {
        return $this->responseStatusCode;
    }

    public function errors(): array
    {
        return $this->errors;
    }
}
