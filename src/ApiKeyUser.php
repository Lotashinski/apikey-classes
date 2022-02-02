<?php
declare(strict_types=1);

namespace Grsu\ApiKeySecurity;

use Symfony\Component\Security\Core\User\UserInterface;

class ApiKeyUser implements UserInterface
{
    /**
     * @var string[]
     */
    private array $roles = [];
    private string $identifier;

    /**
     * @var string[]|null
     */
    private ?array $allowIps = null;

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    public function eraseCredentials()
    {
    }

    /**
     * @param string[] $roles
     */
    public function setRoles(array $roles): self
    {
        $this->roles = $roles;
        return $this;
    }

    public function setIdentifier(string $identifier): self
    {
        $this->identifier = $identifier;
        return $this;
    }

    public function getAllowIps(): ?array
    {
        return $this->allowIps;
    }

    public function setAllowIps(?array $allowIps): void
    {
        $this->allowIps = $allowIps;
    }
}