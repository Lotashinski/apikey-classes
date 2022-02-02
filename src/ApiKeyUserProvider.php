<?php
declare(strict_types=1);

namespace Grsu\ApiKeySecurity;

use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Yaml\Yaml;

class ApiKeyUserProvider implements UserProviderInterface
{
    private ?array $apiUsers = null;


    public function __construct(
        private LoggerInterface $logger,
        private string          $pathToUsersConfig
    )
    {
    }

    /**
     * @throws UnsupportedUserException
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof ApiKeyUser) {
            throw new UnsupportedUserException('Expected ' . ApiKeyUser::class . ', but received ' . $user::class);
        }
        return $user;
    }

    /**
     * @param class-string $class
     */
    public function supportsClass(string $class): bool
    {
        return ApiKeyUser::class === $class || is_subclass_of($class, ApiKeyUser::class);
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $this->logger->debug('Find user by identified:' . $identifier);
        return $this->loadUser($identifier);
    }

    /**
     * @throws UserNotFoundException
     */
    private function loadUser(string $apikey): ApiKeyUser
    {
        $users = $this->getUsersArray();

        foreach ($users as $fileUser) {
            if ($fileUser['api_key'] === $apikey) {
                return $this->configureUser($fileUser);
            }
        }

        throw new UserNotFoundException('User not found in user storage');
    }

    private function getUsersArray(): array
    {
        if ($this->apiUsers === null) {
            $this->logger->debug('Load users from config file', ['file' => $this->pathToUsersConfig]);
            $this->apiUsers = Yaml::parseFile($this->pathToUsersConfig);
        }
        return $this->apiUsers['users'];
    }

    private function configureUser(array $userData): ApiKeyUser
    {
        $user = new ApiKeyUser();
        $user->setRoles($userData['roles'])
            ->setIdentifier($userData['user_name']);

        if (isset($userData['ips'])) {
            $user->setAllowIps($userData['ips']);
        }

        return $user;
    }

}