<?php

namespace Grsu\ApiKeySecurity;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;


class ApiKeyAuthentication
    extends AbstractAuthenticator
{

    public const HEADER = 'X-AUTH-KEY';

    private LoggerInterface $logger;


    public function __construct(
        LoggerInterface $logger
    )
    {
        $this->logger = $logger;
    }


    public function supports(Request $request): ?bool
    {
        $isSupport = $request->headers->has(self::HEADER);

        $this->logger->debug('Check request Authenticator support', [
            'isSupport' => $isSupport,
            'headers' => $request->headers->all(),
        ]);;

        return $isSupport;
    }

    public function authenticate(Request $request): Passport
    {
        $userBadge = new UserBadge($request->headers->get(self::HEADER));

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
        return null;
    }

}