<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Cake\Chronos\Chronos;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Laravel\Socialite\Facades\Socialite;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;
use Pterodactyl\Services\Users\UserCreationService;

class LoginController extends AbstractLoginController
{
    /**
     * @var \Illuminate\Contracts\View\Factory
     */
    private $view;

    /**
     * @var \Illuminate\Contracts\Cache\Repository
     */
    private $cache;

    /**
     * @var \Pterodactyl\Contracts\Repository\UserRepositoryInterface
     */
    private $repository;

    /**
     * @var \Pterodactyl\Services\Users\UserCreationService
     */
    private $creationService;

    /**
     * LoginController constructor.
     *
     * @param \Illuminate\Auth\AuthManager $auth
     * @param \Illuminate\Contracts\Config\Repository $config
     * @param \Illuminate\Contracts\Cache\Repository $cache
     * @param \Pterodactyl\Contracts\Repository\UserRepositoryInterface $repository
     * @param \Illuminate\Contracts\View\Factory $view
     * @param \Pterodactyl\Services\Users\UserCreationService $creationService
     */
    public function __construct(
        AuthManager $auth,
        Repository $config,
        CacheRepository $cache,
        UserRepositoryInterface $repository,
        ViewFactory $view,
        UserCreationService $creationService
    ) {
        parent::__construct($auth, $config);

        $this->view = $view;
        $this->cache = $cache;
        $this->repository = $repository;
        $this->creationService = $creationService;
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component. Vuejs will take over at this point and
     * turn the login area into a SPA.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function index(): View
    {
        return $this->view->make('templates/auth.core');
    }

    /**
     * Handle a login request to the application.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        $username = $request->input('user');
        $useColumn = $this->getField($username);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        try {
            $user = $this->repository->findFirstWhere([[$useColumn, '=', $username]]);
        } catch (RecordNotFoundException $exception) {
            return $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceede to the next step in the login process.
        if (! password_verify($request->input('password'), $user->password)) {
            return $this->sendFailedLoginResponse($request, $user);
        }

        if ($user->use_totp) {
            $token = Str::random(64);
            $this->cache->put($token, $user->id, Chronos::now()->addMinutes(5));

            return JsonResponse::create([
                'data' => [
                    'complete' => false,
                    'confirmation_token' => $token,
                ],
            ]);
        }

        $this->auth->guard()->login($user, true);

        return $this->sendLoginResponse($user, $request);
    }

    /**
     * Redirect the user to the socialite driver.
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function redirectToProvider()
    {
        return Socialite::driver('oauth2')->redirect();
    }

    /**
     * Obtain the user information from Socialite.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function handleProviderCallback(Request $request): JsonResponse
    {
        $user = Socialite::driver('oauth2')->user();

        if ($user) {
            try {
                $user = $this->repository->findFirstWhere([['external_id', '=', $user->getId()]]);
            } catch (RecordNotFoundException $exception) {
                $lastName = (strpos($user->getName(), ' ') === false) ? '' : preg_replace('#.*\s([\w-]*)$#', '$1', $user->getName());
                $firstName = trim(preg_replace('#'.$lastName.'#', '', $user->getName()));

                $user = $this->creationService->handle([
                    'external_id' => $user->getId(),
                    'email' => $user->getEmail(),
                    'username' => $user->getNickname(),
                    'name_first' => $firstName,
                    'name_last' => $lastName,
                    'root_admin' => false,
                ], false);
            }

            $this->auth->guard()->login($user, true);

            return $this->sendLoginResponse($user, $request);
        } else {
            return $this->sendFailedLoginResponse($request);
        }
    }
}
