<?php
namespace UrbanBrussels\KeycloakApi;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class KeycloakApi
{
    private HttpClientInterface $httpClient;
    private ParameterBagInterface $params;
    private string $accessToken;
    private string $realm;
    private string $keycloakBaseUrl;
    private ?int $tokenExpiresAt = null;

    public function __construct(HttpClientInterface $httpClient, ParameterBagInterface $params)
    {
        $this->httpClient = $httpClient;
        $this->params = $params;
        $this->keycloakBaseUrl = $this->params->get('OAUTH_KEYCLOAK_URL');
        $this->realm = $this->params->get('OAUTH_KEYCLOAK_REALM');
    }

    private function getToken(): string
    {
        if ($this->isTokenExpired()) {
            $this->accessToken = $this->createToken();
        }

        return $this->accessToken;
    }

    private function isTokenExpired(): bool
    {
        return $this->tokenExpiresAt === null || time() >= $this->tokenExpiresAt;
    }

    // Access Token
    private function createToken(): string
    {
        $response = $this->httpClient->request('POST', $this->keycloakBaseUrl.'/realms/' . $this->realm . '/protocol/openid-connect/token', [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'client_id' => $this->params->get('OAUTH_KEYCLOAK_CLIENT_ID'),
                'client_secret' => $this->params->get('OAUTH_KEYCLOAK_CLIENT_SECRET'),
                'username' => $this->params->get('KEYCLOAK_USERNAME'),
                'password' => $this->params->get('KEYCLOAK_PASSWORD'),
                'grant_type' => 'password',
            ]
        ]);

        $data = $response->toArray();
        $this->tokenExpiresAt = time() + $data['expires_in'];

        return $data['access_token'];
    }

    // Get user group
    public function getUserGroup(string $userId): string
    {
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl.'/admin/realms/' . $this->realm . '/users/' . $userId . '/groups', [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
            ]
        ]);
        $groups = json_decode($response->getContent());
        return $groups[0]->id;
    }

    // Get users from the group
    public function getUsersFromGroupId(string $groupId): array
    {
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/groups/'.$groupId.'/members', [
            'headers' => [
                'Authorization' => 'Bearer '.$this->getToken(),
            ]
        ]);

        $users = json_decode($response->getContent(), true);

        // Sort users by lastName, firstName
        usort($users, function($a, $b) {
            // Comparison by lastName
            $lastCompare = strcmp($a['lastName'], $b['lastName']);
            if ($lastCompare === 0) {
                // If it's the same lastName, check firstName
                return strcmp($a['firstName'], $b['firstName']);
            }
            return $lastCompare;
        });

        return $users;
    }

    // Get user information
    public function getUserInfo(string $userId): array
    {
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl.'/admin/realms/' . $this->realm . '/users/' . $userId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
            ]
        ]);

        return $response->toArray();
    }

    // Get group information
    public function getGroupInfo(string $groupId): array
    {
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl.'/admin/realms/' . $this->realm . '/groups/' . $groupId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
            ]
        ]);

        return $response->toArray();
    }

    // Create user in the Realm
    public function createUser(array $userData): string
    {
        $userData['enabled'] = true;

        $response = $this->httpClient->request('POST', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/users', [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
                'Content-Type' => 'application/json',
            ],
            'json' => $userData,
        ]);

        $locationHeader = $response->getHeaders()['location'][0];
        return basename($locationHeader);
    }

    // Add user to group
    public function addUserToGroup(string $userId, string $groupId): bool
    {
        $response = $this->httpClient->request('PUT', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/users/'.$userId.'/groups/'.$groupId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
                'Content-Type' => 'application/json',
            ],
        ]);

        // Check success
        if ($response->getStatusCode() !== 204) {
            throw new HttpException($response->getStatusCode(), 'Failed to add user to group');
        }

        return $response->getStatusCode() === 204;
    }

    // Update user information
    public function updateUser(string $userId, array $userData): bool
    {
        $response = $this->httpClient->request('PUT', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/users/'.$userId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
                'Content-Type' => 'application/json',
            ],
            'json' => $userData,
        ]);

        if ($response->getStatusCode() !== 204) {
            throw new HttpException($response->getStatusCode(), 'Failed to update user data');
        }

        return true;
    }

    // Delete user
    public function deleteUser(string $userId): bool
    {
        $response = $this->httpClient->request('DELETE', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/users/'.$userId, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
            ]
        ]);

        // Check if user was deleted as requested
        if ($response->getStatusCode() !== 204) {
            throw new HttpException($response->getStatusCode(), 'Failed to delete user');
        }

        return $response->getStatusCode() === 204;
    }
}