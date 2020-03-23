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

class SocialiteLoginController extends AbstractLoginController
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
    protected $creationService;

    /**
     * SocialiteLoginController constructor.
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
     * Redirect the user to the socialite driver.
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function redirectToProvider()
    {
        return Socialite::driver('github')->redirect();
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
        $user = Socialite::driver('github')->user();

        try {
            $user = $this->repository->findFirstWhere([['external_id', '=', $user->getId()]]);
        } catch (RecordNotFoundException $exception) {
            $lastName = (strpos($user->getName(), ' ') === false) ? '' : preg_replace('#.*\s([\w-]*)$#', '$1', $user->getName());
            $firstName = trim( preg_replace('#'.$lastName.'#', '', $user->getName()));

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
    }
}
