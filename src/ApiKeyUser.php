<?php

namespace Grsu\ApiKeySecurity;

use Symfony\Component\Security\Core\User\UserInterface;

class ApiKeyUser
    implements UserInterface
{
    /**
     * @var string[]
     */
    private array $roles = [];
    private string $identifier;


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

}