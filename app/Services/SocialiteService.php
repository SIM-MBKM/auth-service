<?php

namespace App\Services;

use App\DTOs\IdentityCheckDTO;
use App\DTOs\IdentityCheckResponseDTO;
use App\DTOs\UserDTO;
use App\Models\User;
use App\Repositories\UserIdentityRepository;
use App\Repositories\UserRepository;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use App\Services\QueueService;
use RuntimeException;

class SocialiteService
{
    public function __construct(
        private UserRepository $userRepository,
        private UserIdentityRepository $userIdentityRepository,
        private QueueService $queueService
    ) {
        $this->userRepository = $userRepository;
        $this->userIdentityRepository = $userIdentityRepository;
        $this->queueService = $queueService;
    }

    public function handleSocialLogin(string $provider, SocialiteUser $socialUser): User
    {
        try {
            $identity = $this->userIdentityRepository->findOrNewIdentity($provider, $socialUser->getId());

            if (!$identity->exists) {
                $user = $this->findOrCreateUser($socialUser);
                $identity->user_id = $user->id;
                $identity->provider_data = $this->formatProviderData($socialUser);
            } else {
                $user = $identity->user;
                $identity->provider_data = $this->formatProviderData($socialUser);
            }

            $this->updateIdentityTokens(
                $identity,
                $socialUser->token,
                $socialUser->refreshToken,
                $socialUser->expiresIn
            );

            return $user;
        } catch (\Exception $e) {
            Log::error("Social login failed for {$provider}: " . $e->getMessage(), [
                'provider' => $provider,
                'social_id' => $socialUser->getId(),
                'error' => $e
            ]);
            throw new RuntimeException('Social authentication failed', 401, $e);
        }
    }

    public function checkEmailIdentity(IdentityCheckDTO $dto): IdentityCheckResponseDTO
    {
        try {
            // Check if user exists
            $user = $this->userRepository->findByEmail($dto->email);
            $userExists = $user !== null;

            // Determine provider based on email domain
            $provider = $this->getProviderByEmail($dto->email);

            return new IdentityCheckResponseDTO(
                email: $dto->email,
                userExists: $userExists,
                provider: $provider
            );

        } catch (\Exception $e) {
            Log::error('Email identity check failed: ' . $e->getMessage(), [
                'email' => $dto->email,
                'error' => $e
            ]);
            throw new RuntimeException('Identity check failed', 500, $e);
        }
    }

    private function getProviderByEmail(string $email): string
    {
        $domain = explode('@', $email)[1];
        
        // ITS domains use microsoft, others use google
        return in_array($domain, ['its.ac.id', 'student.its.ac.id', 'geofisika.its.ac.id']) 
            ? 'sso' 
            : 'google';
    }

    // public function handleSocialLogin(string $provider, SocialiteUser $socialUser): User
    // {
    //     Log::info("[1] Social login started", ['provider' => $provider]);

    //     try {
    //         Log::info("[2] Searching identity", [
    //             'provider' => $provider,
    //             'social_id' => $socialUser->getId()
    //         ]);

    //         $identity = $this->userIdentityRepository->findOrNewIdentity($provider, $socialUser->getId());
    //         dd($identity);
    //         if (!$identity->exists) {
    //             Log::info("[3] New identity detected");
    //             $user = $this->findOrCreateUser($socialUser);
    //             $identity->user_id = $user->id;
    //             $identity->provider_data = $this->formatProviderData($socialUser);
    //         } else {
    //             Log::info("[4] Existing identity found");
    //             $user = $identity->user;
    //             $identity->provider_data = $this->formatProviderData($socialUser);
    //         }

    //         Log::info("[5] Saving identity");
    //         $identity->save();

    //         return $user;
    //     } catch (\Exception $e) {
    //         Log::error("[ERROR] Social login failed", ['error' => $e->getMessage()]);
    //         throw $e;
    //     }
    // }

    private function findOrCreateUser(SocialiteUser $socialUser): User
    {
        try {
            $user = $this->userRepository->findByEmail($socialUser->getEmail());

            return $user ?? $this->createUserFromSocial($socialUser);
        } catch (\Exception $e) {
            Log::error('User lookup/creation failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to process user account', 500, $e);
        }
    }

    private function createUserFromSocial(SocialiteUser $socialUser): User
    {
        try {
            $dto = UserDTO::fromSocialite($socialUser);
            $user = $this->userRepository->createUser($dto);

            $this->queueService->publishUserEvent('created', [
                'auth_user_id' => $user->id,
                'email' => $user->email,
            ]);

            return $user;
        } catch (\Exception $e) {
            Log::error('User creation failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to create user account', 500, $e);
        }
    }

    private function updateIdentityTokens($identity, string $token, ?string $refreshToken, ?int $expiresIn): void
    {
        try {
            $this->userIdentityRepository->updateIdentityTokens(
                $identity,
                $token,
                $refreshToken,
                $expiresIn
            );
        } catch (\Exception $e) {
            Log::error('Identity token update failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to update authentication tokens', 500, $e);
        }
    }

    private function formatProviderData(SocialiteUser $socialUser): array
    {
        try {
            return [
                'name' => $socialUser->getName(),
                'email' => $socialUser->getEmail(),
                'avatar' => $socialUser->getAvatar(),
            ];
        } catch (\Exception $e) {
            Log::error('Provider data formatting failed: ' . $e->getMessage());
            throw new RuntimeException('Invalid social provider data', 400, $e);
        }
    }
}
