<?php
declare(strict_types=1);

namespace Grsu\ApiKeySecurity;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class ApiKeyAuthentication extends AbstractAuthenticator
{

    public function __construct(
        private LoggerInterface $logger,
        private string          $header = 'X-AUTH-KEY',
        private bool            $strictVerification = true
    )
    {
    }


    public function supports(Request $request): ?bool
    {

        $isSupport = $this->strictVerification || $request->headers->has($this->header);

        $this->logger->debug('Check request Authenticator support', [
            'isSupport' => $isSupport,
            'headers-key' => $request->headers->get($this->header),
        ]);

        return $isSupport;
    }

    public function authenticate(Request $request): Passport
    {
        $userBadge = new UserBadge($request->headers->get($this->header) ?? '');

        $credentialChecker = new CustomCredentials(
            function (?string $ip, ApiKeyUser $user) {
                if ($user->getAllowIps() === null)
                    return true;
                return $ip !== null && in_array($ip, $user->getAllowIps());
            },
            $request->getClientIp()
        );

        return new Passport($userBadge, $credentialChecker);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        throw new AccessDeniedException("Authentication Failure.");
    }
}