<?php

namespace App\Controllers;

use App\Repositories\UserRepository;
use App\Services\AccessTokenService;
use App\Services\SocialiteService;
use App\Services\UserService;
use Exception;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Log;

class AuthController
{
    protected $accessTokenService;
    protected $apiKeyService;
    protected $userRepository;
    protected $socialiteService;

    public function __construct(
        AccessTokenService $accessTokenService,
        SocialiteService $socialiteService,
        UserRepository $userRepository
    ) {
        $this->accessTokenService = $accessTokenService;
        $this->socialiteService = $socialiteService;
        $this->userRepository = $userRepository;
    }

    /**
     * Redirect to Google
     */
    public function redirectToGoogle()
    {
        return Socialite::driver('google')->redirect();
    }

    /**
     * Handle Google callback
     */
    public function handleGoogleCallback(Request $request)
    {
        try {
            $googleUser = Socialite::driver('google')->stateless()->user();
            $user = $this->socialiteService->handleSocialLogin('google', $googleUser);

            $this->accessTokenService->logLogin($user->id, $request, 'google', true);
            $token = $this->accessTokenService->generateToken($user, $request);

            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'user' => collect($user)->merge(['user_id' => $user->id])
            ]);
        } catch (\RuntimeException $e) {
            $this->accessTokenService->logLogin(null, $request, 'google', false, $e->getMessage());
            Log::warning("Google auth error: {$e->getMessage()}");
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'google', false, $e->getMessage());
            Log::error("Google auth failed: {$e->getMessage()}");
            return response()->json(['error' => 'Authentication failed'], 500);
        }
    }

    /**
     * Validate JWT Token
     */
    public function validateToken(Request $request)
    {
        try {
            $token = $request->bearerToken();

            if (!$token) {
                $token = $request->input('token');
                Log::info($token);
                if (!$token) {
                    throw new \RuntimeException('No token provided', 400);
                }
            }

            $user = $this->accessTokenService->getUserFromToken($token);
            Log::info($user);

            return response()->json([
                'success' => true,
                'data' => collect($user)->merge(['user_id' => $user->id])
            ]);
        } catch (\RuntimeException $e) {
            $this->accessTokenService->logLogin(null, $request, 'google', false, $e->getMessage());
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'google', false, $e->getMessage());
            return response()->json(['error' => 'Token validation failed'], 500);
        }
    }

    /**
     * Logout
     */
    public function logout(Request $request)
    {
        try {
            $token = $request->bearerToken();
            if (!$token) {
                throw new \RuntimeException('No token provided', 400);
            }

            $success = $this->accessTokenService->deleteToken($token);
            if (!$success) {
                throw new \RuntimeException('Token not found', 404);
            }

            return response()->json(['message' => 'Logged out']);
        } catch (\RuntimeException $e) {
            $this->accessTokenService->logLogin(null, $request, 'logout', false, $e->getMessage());
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'logout', false, $e->getMessage());
            Log::error("Logout error: {$e->getMessage()}");
            return response()->json(['error' => 'Logout failed'], 500);
        }
    }

    /**
     * Get current user
     */
    public function getUser(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Unauthorized');
                throw new \RuntimeException('Unauthorized', 401);
            }

            return response()->json([
                'user' => $user,
                'identities' => $this->accessTokenService->getIdentities($user->id)
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            Log::error("Get user error: {$e->getMessage()}");
            return response()->json(['error' => 'Failed to retrieve user'], 500);
        }
    }

    /**
     * Refresh token
     */
    public function refreshToken(Request $request)
    {
        try {
            $token = $request->bearerToken();
            if (!$token) {
                throw new \RuntimeException('No token provided', 400);
            }

            $user = $this->accessTokenService->getUserFromToken($token);
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'refresh_token', false, 'Invalid token');
                throw new \RuntimeException('Invalid token', 401);
            }

            $this->accessTokenService->deleteToken($token);
            $newToken = $this->accessTokenService->generateToken($user, $request);

            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'user' => $user
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'refresh_token', false, $e->getMessage());
            Log::error("Refresh error: {$e->getMessage()}");
            return response()->json(['error' => 'Token refresh failed'], 500);
        }
    }
}
