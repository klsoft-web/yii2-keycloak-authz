# YII2-KEYCLOAK-AUTHZ

 The package provides Keycloak authorization for the web service APIs of [Yii 2](https://www.yiiframework.com).

 See also:

 -  [YII2-JWT-AUTH](https://github.com/klsoft-web/yii2-jwt-auth) - The package provides a [Yii 2](https://www.yiiframework.com) authentication method based on a JWT token
 -  [PHP-KEYCLOAK-CLIENT](https://github.com/klsoft-web/php-keycloak-client) - A PHP library that can be used to secure web applications with Keycloak

## Requirement

 - PHP 8.0 or higher.

## Installation

```bash
composer require klsoft/yii2-keycloak-authz
```

## How does it work
 1. A client requests a protected web service API method using an access token.
 2. The web service checks whether the access token contains the necessary permissions. If permissions exist, proceed to step 6.
 3. The web service obtains a permission ticket using the access token and the permissions of the API method. It then responds with the permission ticket: `HTTP/1.1 401 Unauthorized WWW-Authenticate: UMA realm="realm name", as_uri="realm URI", ticket="permission ticket"`
 4. The client obtains a Requesting Party Token (RPT) using the access token and the permission ticket.
 5. The client requests a protected web service API method with the RPT.
 6. The web service checks the RPT permissions. If the RPT has the necessary permissions, the request is passed to the next ActionFilter or action. Otherwise, HTTP/1.1 403 Forbidden is returned

## How to use

### 1. Implement Klsoft\Yii2KeycloakAuthz\KeycloakRepositoryInterface

Example:

```php
namespace MyNamespace;

use Klsoft\Yii2KeycloakAuthz\KeycloakRepositoryInterface;
use Klsoft\Yii2KeycloakAuthz\PermissionTicketResult;
use Klsoft\Yii2KeycloakAuthz\PermissionTicketResponse;

final class KeycloakRepository implements KeycloakRepositoryInterface
{
    public function __construct(
        private string $realm,
        private string $realmUri)
    {
    }

    public function getPermissionTicket(string $accessToken, array $permissions): PermissionTicketResult
    {
        $url = "$this->realmUri/authz/protection/permission";
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => [
                    'Content-type: application/json',
                    "Authorization: Bearer $accessToken"],
                'content' => json_encode($permissions)
            ],
        ];
        $responseData = file_get_contents($url, false, stream_context_create($options));
        $responseStatusCode = $this->getHttpResponseStatusCode($http_response_header[0]);
        if (!empty($responseData)) {
            $responseArr = json_decode($responseData, true);
            if (isset($responseArr['ticket'])) {
                return new PermissionTicketResult(
                    new PermissionTicketResponse(
                        $this->realm, 
                        $this->realmUri, 
                        $responseArr['ticket']));
            }
            return new PermissionTicketResult(null, $responseStatusCode, $responseArr);
        }

        return new PermissionTicketResult(null, $responseStatusCode);
    }

    private function getHttpResponseStatusCode(string $responseHeader): int
    {
        if (preg_match("/^HTTP\/[\d.]+\s+(\d{3})\s.*$/", $responseHeader, $matches)) {
            return intval($matches[1]);
        }
        return 0;
    }
}
```

### 2. Add the realm and the realm URI to param.php

Example:

```php
return [
    'realm' => 'myrealm',
    'realmUri' => 'http://localhost:8080/realms/myrealm'
];
```

### 3. Register dependencies

Example of registering dependencies using the application configuration:

```php
use Klsoft\Yii2KeycloakAuthz\Authorization;
use Klsoft\Yii2KeycloakAuthz\KeycloakRepositoryInterface;

'container' => [
        'definitions' => [
            Authorization::class => [
                Authorization::class,
                [Instance::of(KeycloakRepositoryInterface::class)]
            ]
        ],
        'singletons' => [
            KeycloakRepositoryInterface::class => [
                KeycloakRepository::class,
                [
                    $params['realm'],
                    $params['realmUri']
                ]
            ]
        ]
    ]
```

### 4. Apply permissions.

#### 4.1.  Configure the `authorization` behavior and apply permissions to an action

Example:

```php
use yii\rest\Controller;
use Klsoft\Yii2JwtAuth\HttpJwtAuth;
use Klsoft\Yii2KeycloakAuthz\Authorization;
use Klsoft\Yii2KeycloakAuthz\Permission;

class ProductController extends Controller
{
    public function __construct(
        private HttpJwtAuth $httpJwtAuth, 
        private Authorization $authz, 
        private ProductPresenterInterface $productPresenter)
    {
    }

    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['authentication'] = $this->httpJwtAuth;
        $behaviors['authorization'] = $this->authz;
        return $behaviors;
    }
    
    #[Permission(
        'product',
        ['create']
    )]
    public function actionCreate()
    {
        return $this->productPresenter->createProduct(Yii::$app->getRequest());
    }
}
```

Example of a permission with claims:

```php
#[Permission(  
    'product',  
    ['create'],  
    ['organization' => ['acme']]  
)]
public function actionCreate()
```

Example of a permission with an executing claim value:

```php
#[Permission(  
    'product',  
    ['create'],  
    ['organization' => [  
        '__container_entry_identifier',  
        OrganizationPresenterInterface::class,  
        'getOrganizationName',  
        ['__request']]  
    ]  
)]
public function actionCreate()
```

#### 4.2.  Configure the `authorization` behavior and apply permissions to a controller

Example:

```php
use yii\rest\Controller;
use Klsoft\Yii2JwtAuth\HttpJwtAuth;
use Klsoft\Yii2KeycloakAuthz\Authorization;
use Klsoft\Yii2KeycloakAuthz\Permission;

final class ProductController extends Controller
{
    public function __construct(
        private HttpJwtAuth $httpJwtAuth, 
        private Authorization $authz, 
        private ProductPresenterInterface $productPresenter)
    {
    }

    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['authentication'] = $this->httpJwtAuth;
        $behaviors['authorization'] = $this->authz->withPermissions([
            new Permission(
                'product',
                ['create']
            ),
            new Permission(
                'product',
                ['update']
            )
        ]);
        return $behaviors;
    }
}
```
