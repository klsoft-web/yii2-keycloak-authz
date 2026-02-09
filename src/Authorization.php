<?php

namespace Klsoft\Yii2KeycloakAuthz;

use DomainException;
use UnexpectedValueException;
use ReflectionException;
use ReflectionClass;
use stdClass;
use Yii;
use yii\base\ActionFilter;
use yii\web\Request;
use yii\web\Response;

class Authorization extends ActionFilter
{
    private string $headerName = 'Authorization';
    private string $headerTokenPattern = '/^Bearer\s+(.*?)$/';
    private array $permissions = [];

    public function __construct(
        private KeycloakRepositoryInterface $keycloakRepository,
        private ?JwtDecoderInterface        $jwtDecoder = null)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function beforeAction($action)
    {
        $request = Yii::$app->getRequest();
        $response = Yii::$app->getResponse();

        $actioPermissions = empty($this->permissions) ? $this->getActionPermissions($request) : array_map(fn($permission) => $this->callPermissionClaimsUserFunc($permission, $request), $this->permissions);
        if (!empty($actioPermissions)) {
            $token = $this->getAuthorizationToken($request);
            if ($token !== null) {
                try {
                    $jwtPayload = ($this->jwtDecoder !== null ? $this->jwtDecoder : new JwtDecoder())->decode($token);
                    if (property_exists($jwtPayload, 'authorization')) {
                        if ($this->tokenHasPermissions($jwtPayload->authorization, $actioPermissions)) {
                            $bodyParams = (array)$request->getBodyParams();
                            $bodyParams[self::class] = $jwtPayload;
                            $request->setBodyParams($bodyParams);
                            return true;
                        } else {
                            $this->forbiddenResponse($response, ['error' => 'access_denied']);
                            return false;
                        }
                    } else {
                        $permissionTicketResult = $this->keycloakRepository->getPermissionTicket(
                            $token,
                            $this->convertToRequestPermissionTicketFormat($actioPermissions));
                        $permissionTicketResponse = $permissionTicketResult->permissionTicketResponse();
                        if ($permissionTicketResponse !== null) {
                            $response->statusCode = 401;
                            $response->headers->set('WWW-Authenticate', "UMA realm=\"{$permissionTicketResponse->realm()}\", as_uri=\"{$permissionTicketResponse->asUri()}\", ticket=\"{$permissionTicketResponse->ticket()}\"");
                        } else {
                            $response->statusCode = $permissionTicketResult->responseStatusCode();
                            $response->format = Response::FORMAT_JSON;
                            $response->data = $permissionTicketResult->errors();
                        }
                        return false;
                    }
                } catch (DomainException|UnexpectedValueException) {
                    $this->forbiddenResponse($response);
                    return false;
                }
            } else {
                $this->forbiddenResponse($response);
                return false;
            }
        }

        return true;
    }

    private function getActionPermissions(Request $request): array
    {
        $actionPermissions = [];
        $routeWithParams = Yii::$app->urlManager->parseRequest($request);
        if (!empty($routeWithParams)) {
            try {
                $routeArr = explode('/', $routeWithParams[0]);
                $controllerNamespace = Yii::$app->controllerNamespace;
                if (count($routeArr) == 2 &&
                    !empty($controllerNamespace)) {
                    $refClass = new ReflectionClass("$controllerNamespace\\" . ucfirst($routeArr[0]) . "Controller");
                    $refMethod = $refClass->getMethod("action" . ucfirst($routeArr[1]));
                    $attributes = $refMethod->getAttributes(Permission::class);
                    foreach ($attributes as $attribute) {
                        $arguments = $attribute->getArguments();
                        if (!empty($arguments)) {
                            $claims = $arguments[2] ?? [];
                            foreach ($claims as $key => $value) {
                                $claims[$key] = $this->callClaimValueUserFunc($value, $request);
                            }
                            $actionPermissions[] = new Permission(
                                $arguments[0],
                                $arguments[1] ?? [],
                                $claims);
                        }
                    }
                }
            } catch (ReflectionException) {
                return [];
            }
        }

        return $actionPermissions;
    }

    private function callPermissionClaimsUserFunc(
        Permission $permission,
        Request    $request): Permission
    {
        $claims = $permission->claims();
        foreach ($claims as $key => $value) {
            $claims[$key] = $this->callClaimValueUserFunc($value, $request);
        }
        return new Permission(
            $permission->resource(),
            $permission->scopes(),
            $claims);
    }

    private function callClaimValueUserFunc(
        mixed   $claimValue,
        Request $request): mixed
    {
        if (is_array($claimValue) &&
            count($claimValue) > 2 &&
            $claimValue[0] === '__container_entry_identifier') {
            $args = $claimValue[3] ?? [];
            for ($i = 0; $i < count($args); $i++) {
                if ($args[$i] === '__request') {
                    $args[$i] = $request;
                }
            }
            return call_user_func_array(
                array(Yii::$container->get($claimValue[1]), $claimValue[2]),
                $args);
        }

        return $claimValue;
    }

    private function forbiddenResponse(
        Response $response,
        array    $errors = ['error' => 'invalid_bearer_token']): void
    {
        $response->statusCode = 403;
        $response->format = Response::FORMAT_JSON;
        $response->data = $errors;
    }

    private function getAuthorizationToken($request): ?string
    {
        $authHeader = $request->getHeaders()->get($this->headerName);
        if (!empty($authHeader) && preg_match($this->headerTokenPattern, $authHeader, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function tokenHasPermissions(
        stdClass $authorization,
        array    $actionPermissions): bool
    {
        if (property_exists($authorization, 'permissions') &&
            is_array($authorization->permissions)) {
            $jwtPermissions = $authorization->permissions;
            foreach ($actionPermissions as $actionPermission) {
                $isResourceFound = false;
                foreach ($jwtPermissions as $jwtPermission) {
                    if ($actionPermission->resource() === $jwtPermission->rsname) {
                        $isResourceFound = true;

                        foreach ($actionPermission->scopes() as $actionScope) {
                            if (!in_array($actionScope, $jwtPermission->scopes)) {
                                return false;
                            }
                        }

                        foreach ($actionPermission->claims() as $actionClaimKey => $actionClaimValues) {
                            $actionClaimValues = is_array($actionClaimValues) ? $actionClaimValues : [$actionClaimValues];
                            $jwtClaims = $jwtPermission->claims;
                            if (property_exists($jwtClaims, $actionClaimKey)) {
                                $jwtClaimValues = ((array)$jwtClaims)[$actionClaimKey];
                                foreach ($actionClaimValues as $actionClaimValue) {
                                    if (!in_array($actionClaimValue, $jwtClaimValues)) {
                                        return false;
                                    }
                                }
                            } else {
                                return false;
                            }
                        }

                        break;
                    }
                }
                if (!$isResourceFound) {
                    return false;
                }
            }
        } else {
            return false;
        }

        return true;
    }

    private function convertToRequestPermissionTicketFormat(array $actionPermissions): array
    {
        $permissions = [];
        foreach ($actionPermissions as $actionPermission) {
            $permissions[] = [
                "resource_id" => $actionPermission->resource(),
                "resource_scopes" => $actionPermission->scopes(),
                "claims" => $actionPermission->claims()];
        }

        return $permissions;
    }

    /**
     * @param string $headerName Authorization header name.
     *
     * @return self
     */
    public function withHeaderName(string $headerName): self
    {
        $new = clone $this;
        $new->headerName = $headerName;
        return $new;
    }

    /**
     * @param string $headerTokenPattern Regular expression to use for getting a token from authorization header.
     * Token value should match first capturing group.
     *
     * @return self
     */
    public function withHeaderTokenPattern(string $headerTokenPattern): self
    {
        $new = clone $this;
        $new->headerTokenPattern = $headerTokenPattern;
        return $new;
    }

    /**
     * @param array $permissions - The array contains instances of the Klsoft\Yii2KeycloakAuthz\Permission class.
     *
     * @return self
     */
    public function withPermissions(array $permissions): self
    {
        $new = clone $this;
        $new->permissions = array_filter($permissions, fn($item) => $item instanceof Permission);
        return $new;
    }
}