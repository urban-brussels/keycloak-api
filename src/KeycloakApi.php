<?php
namespace UrbanBrussels\KeycloakApi;

use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
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
                'Authorization' => 'Bearer ' . $this->getToken(),
            ],
            'query' => [
                'first' => 0,
                'max' => 1000,
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

    /**
     * Retrouve les informations d'un groupe en parcourant l'arborescence à partir de son chemin complet.
     *
     * @param string $groupPath Le chemin complet du groupe (ex: "/Communes/Anderlecht").
     * @return array Les informations du groupe ou un tableau vide si non trouvé.
     */
    public function getGroupInfoByPath(string $groupPath): array
    {
        // Nettoyer et décomposer le chemin en segments. Ex: "/Communes/Anderlecht" -> ['Communes', 'Anderlecht']
        $segments = array_filter(explode('/', $groupPath));
        if (empty($segments)) {
            return []; // Chemin invalide ou racine
        }

        // On stocke le premier segment avant de le retirer du tableau
        $firstSegment = array_shift($segments);

        // Étape 1 : Trouver le groupe de premier niveau
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl . '/admin/realms/' . $this->realm . '/groups', [
            'headers' => ['Authorization' => 'Bearer ' . $this->getToken()],
            'query' => [
                'search' => $firstSegment, // On cherche le premier segment
                'exact' => 'true'
            ]
        ]);
        $topLevelGroups = json_decode($response->getContent(), true);

        // On s'assure de trouver un seul groupe de premier niveau avec le bon nom
        $currentGroup = null;
        foreach ($topLevelGroups as $group) {
            if ($group['name'] === $firstSegment) {
                $currentGroup = $group;
                break;
            }
        }

        if (!$currentGroup) {
            return []; // Le groupe de départ n'a pas été trouvé
        }

        // Étape 2 : Descendre dans l'arborescence pour chaque segment RESTANT
        foreach ($segments as $segment) {
            $response = $this->httpClient->request('GET', $this->keycloakBaseUrl . '/admin/realms/' . $this->realm . '/groups/' . $currentGroup['id'] . '/children', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->getToken(),
                ],
                'query' => [
                    'first' => 0,
                    'max' => 50,
                ]
            ]);
            $children = json_decode($response->getContent(), true);

            $found = false;
            foreach ($children as $child) {
                if ($child['name'] === $segment) {
                    $currentGroup = $child; // On a trouvé le prochain niveau
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                return []; // Le chemin est invalide, un segment n'a pas été trouvé
            }
        }

        // À la fin de la boucle, $currentGroup contient le groupe final recherché
        return [
            "id" => $currentGroup['id'],
            "name" => $currentGroup['name'],
            "path" => $currentGroup['path'],
        ];
    }

    /**
     * Récupère tous les sous-groupes de tous les niveaux, en excluant les groupes de premier niveau.
     *
     * @return array
     */
    public function getGroups(): array
    {
        // 1. Obtenir uniquement les groupes de premier niveau
        $response = $this->httpClient->request('GET', $this->keycloakBaseUrl . '/admin/realms/' . $this->realm . '/groups', [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
            ]
        ]);
        $topLevelGroups = json_decode($response->getContent(), true);

        $allSubgroups = [];

        // 2. Pour chaque groupe de premier niveau, lancer la recherche récursive des enfants
        foreach ($topLevelGroups as $group) {
            $this->fetchSubgroupsRecursively($group['id'], $allSubgroups);
        }

        return $allSubgroups;
    }

    /**
     * Méthode récursive pour récupérer les descendants d'un groupe en utilisant l'endpoint /children.
     *
     * @param string $groupId L'ID du groupe parent à explorer.
     * @param array &$subgroupsList La liste (passée par référence) pour accumuler les résultats.
     */
    private function fetchSubgroupsRecursively(string $groupId, array &$subgroupsList): void
    {
        $first = 0;
        $max = 50; // On récupère les enfants par lots de 50 pour être efficace

        while (true) {
            // 1. Appel à l'endpoint /children avec les paramètres de pagination
            $response = $this->httpClient->request('GET', $this->keycloakBaseUrl . '/admin/realms/' . $this->realm . '/groups/' . $groupId . '/children', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->getToken(),
                ],
                'query' => [
                    'first' => $first,
                    'max' => $max,
                ]
            ]);

            $children = json_decode($response->getContent(), true);

            // Si la page est vide, cela signifie qu'on a récupéré tous les enfants. On arrête la boucle.
            if (empty($children)) {
                break;
            }

            // 2. Pour chaque enfant trouvé sur cette page...
            foreach ($children as $child) {
                // a. On l'ajoute à notre liste finale
                $subgroupsList[] = [
                    'id' => $child['id'],
                    'name' => $child['name'],
                    'path' => $child['path'],
                ];

                // b. On relance la fonction pour cet enfant afin de trouver ses propres enfants
                $this->fetchSubgroupsRecursively($child['id'], $subgroupsList);
            }

            // 3. Préparer le prochain appel : on décale l'index de départ
            $first += $max;
        }
    }

    // Create user in the Realm
    public function createUser(array $userData, bool $emailVerified = false): string
    {
        $userData['enabled'] = true;
        $userData['emailVerified'] = $emailVerified;

        $response = $this->httpClient->request('POST', $this->keycloakBaseUrl.'/admin/realms/'.$this->realm.'/users', [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getToken(),
                'Content-Type' => 'application/json',
            ],
            'json' => $userData,
        ]);

        $statusCode = $response->getStatusCode();

        // Check for 409 Conflict (user already exists)
        if ($statusCode === 409) {
            throw new ConflictHttpException('A user with this email or username already exists.');
        }

        // Check for a successful creation (201 Created)
        if ($statusCode !== 201) {
            throw new HttpException($statusCode, 'Failed to create the user in Keycloak.');
        }

        // On success, get the new user's ID from the 'location' header
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

    /**
     * Retrouve un groupe à partir de son chemin complet ou partiel (en partant de la fin).
     * C'est la méthode la plus fiable car elle utilise la liste complète des groupes.
     *
     * @param string $partialGroupPath Le chemin partiel du groupe (ex: "/Anderlecht" ou "/Communes/Anderlecht").
     * @return array Les informations du groupe ou un tableau vide si non trouvé.
     */
    public function findGroup(string $partialGroupPath): array
    {
        $cleanedPath = trim($partialGroupPath, '/');
        if (empty($cleanedPath)) {
            return [];
        }
        $normalizedPathSuffix = '/' . $cleanedPath;

        $allGroups = $this->getGroups();

        foreach ($allGroups as $group) {
            if (str_ends_with($group['path'], $normalizedPathSuffix)) {
                return $group; // L'objet groupe contient déjà id, name, path.
            }
        }

        return [];
    }
}
