<?php

namespace Pterodactyl\Extensions\Laravel\Socialite;

use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User;

class OAuth2Provider extends AbstractProvider
{
    /**
     * Get the authentication URL for the provider.
     *
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(config('services.oauth.auth_url'), $state);
    }

    /**
     * Get the token URL for the provider.
     *
     * @return string
     */
    protected function getTokenUrl()
    {
        return config('services.oauth.token_url');
    }

    /**
     * Get the raw user for the given access token.
     *
     * @param string $token
     * @return array
     */
    protected function getUserByToken($token)
    {
        $userUrl = str_replace('{{TOKEN}}', $token, config('services.oauth.user_url'));

        $response = $this->getHttpClient()->get($userUrl);

        $user = json_decode($response->getBody(), true);

        return $user;
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param array $user
     * @return \Laravel\Socialite\Two\User
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map($user);
    }
}
