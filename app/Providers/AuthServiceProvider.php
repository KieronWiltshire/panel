<?php

namespace Pterodactyl\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Pterodactyl\Extensions\Laravel\Socialite\OAuth2Provider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        'Pterodactyl\Models\Server' => 'Pterodactyl\Policies\ServerPolicy',
    ];

    /**
     * Register any application authentication / authorization services.
     */
    public function boot()
    {
        $this->registerPolicies();

        $socialite = $this->app->make('Laravel\Socialite\Contracts\Factory');

        $socialite->extend('oauth2', function ($app) use ($socialite) {
            $config = $app['config']['services.oauth2'];
            return $socialite->buildProvider(OAuth2Provider::class, $config);
        });
    }
}
