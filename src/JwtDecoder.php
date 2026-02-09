<?php

namespace Klsoft\Yii2KeycloakAuthz;

use DomainException;
use UnexpectedValueException;
use DateTime;
use stdClass;

final class JwtDecoder implements JwtDecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $jwt): stdClass
    {
        $timestamp = time();

        $tks = explode('.', $jwt);
        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        if (null === ($payload = $this->jsonDecode($this->urlsafeB64Decode($tks[1])))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        if (is_array($payload)) {
            // prevent PHP Fatal Error in edge-cases when payload is empty array
            $payload = (object) $payload;
        }
        if (!$payload instanceof stdClass) {
            throw new UnexpectedValueException('Payload must be a JSON object');
        }
        if (isset($payload->iat) && !is_numeric($payload->iat)) {
            throw new UnexpectedValueException('Payload iat must be a number');
        }
        if (isset($payload->nbf) && !is_numeric($payload->nbf)) {
            throw new UnexpectedValueException('Payload nbf must be a number');
        }
        if (isset($payload->exp) && !is_numeric($payload->exp)) {
            throw new UnexpectedValueException('Payload exp must be a number');
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && floor($payload->nbf) > $timestamp) {
            throw new UnexpectedValueException('Cannot handle token with nbf prior to ' . date(DateTime::ATOM, (int) floor($payload->nbf)));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (!isset($payload->nbf) && isset($payload->iat) && floor($payload->iat) > $timestamp) {
            throw new UnexpectedValueException('Cannot handle token with iat prior to ' . date(DateTime::ATOM, (int) floor($payload->iat)));
        }

        // Check if this token has expired.
        if (isset($payload->exp) && $timestamp >= $payload->exp) {
            throw new UnexpectedValueException('Expired token');
        }

        return $payload;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public function urlsafeB64Decode(string $input): string
    {
        return base64_decode($this->convertBase64UrlToBase64($input));
    }

    /**
     * Convert a string in the base64url (URL-safe Base64) encoding to standard base64.
     *
     * @param string $input A Base64 encoded string with URL-safe characters (-_ and no padding)
     *
     * @return string A Base64 encoded string with standard characters (+/) and padding (=), when
     * needed.
     *
     * @see https://www.rfc-editor.org/rfc/rfc4648
     */
    public function convertBase64UrlToBase64(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return strtr($input, '-_', '+/');
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return mixed The decoded JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public function jsonDecode(string $input)
    {
        $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     *
     * @throws DomainException
     */
    private function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        ];
        throw new DomainException(
            isset($messages[$errno])
                ? $messages[$errno]
                : 'Unknown JSON error: ' . $errno
        );
    }
}
