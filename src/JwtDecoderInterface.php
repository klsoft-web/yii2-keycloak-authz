<?php

namespace Klsoft\Yii2KeycloakAuthz;

use DomainException;
use UnexpectedValueException;
use stdClass;

interface JwtDecoderInterface
{
    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string $jwt The JWT
     *
     * @return stdClass The JWT's payload as a PHP object
     *
     * @throws DomainException              Provided JWT is malformed
     * @throws UnexpectedValueException     Provided JWT was invalid
     */
    public function decode(string $jwt): stdClass;
}
