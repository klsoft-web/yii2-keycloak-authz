<?php

namespace Klsoft\Yii2KeycloakAuthz;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
final class Permission
{
    /**
     * @param string $resource Keycloak authorization resource name
     * @param array $scopes Keycloak authorization resource scopes
     * @param array $claims Keycloak claims
     */
    public function __construct(
        private string $resource,
        private array  $scopes = [],
        private array  $claims = [])
    {
    }

    public function resource(): string
    {
        return $this->resource;
    }

    public function scopes(): array
    {
        return $this->scopes;
    }

    public function claims(): array
    {
        return $this->claims;
    }
}
