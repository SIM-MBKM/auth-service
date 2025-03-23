<?php

namespace App\Controllers;

use App\DTOs\AccessKeyCreateDTO;
use App\DTOs\UserDTO;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\AccessKey;
use App\Repositories\UserRepository;
use App\Services\AccessKeyService;
use App\Services\AccessTokenService;
use App\Services\SocialiteService;
use Exception;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    protected $accessTokenService;
    protected $accessKeyService;
    protected $userRepository;
    protected $socialiteService;

    public function __construct(
        AccessTokenService $accessTokenService,
        AccessKeyService $accessKeyService,
        SocialiteService $socialiteService,
        UserRepository $userRepository
    ) {
        $this->accessTokenService = $accessTokenService;
        $this->accessKeyService = $accessKeyService;
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
                'user' => $user
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
     * Generate API key
     */
    public function generateAccessKey(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Invalid credentials');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $dto = AccessKeyCreateDTO::fromRequest($request);
            $payload = $this->accessKeyService->createAccessKey($dto, $user->id);

            return response()->json([
                'access_key' => $payload['plain_text_key'],
                'details' => $payload['details']
            ], 201);
        } catch (ValidationException $e) {
            return response()->json([
                'error' => 'Validation Error',
                'messages' => $e->errors()
            ], 422);
        } catch (\RuntimeException $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            Log::error("Key generation error: {$e->getMessage()}");
            return response()->json(['error' => 'Key generation failed'], 500);
        }
    }

    /**
     * List access keys
     */
    public function listAccessKeys(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Unauthorized');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $keys = $this->accessKeyService->listUserKeys($user->id);

            return response()->json([
                'access_keys' => $keys->map(fn($key) => [
                    'id' => $key->id,
                    'description' => $key->description,
                    'scopes' => $key->scopes,
                    'expires_at' => $key->expires_at,
                    'last_used_at' => $key->last_used_at,
                    'is_active' => $key->is_active,
                    'updated_at' => $key->updated_at
                ])
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            Log::error("List keys error: {$e->getMessage()}");
            return response()->json(['error' => 'Failed to list keys'], 500);
        }
    }

    /**
     * Authenticate with access key
     */
    public function authenticateWithKey(Request $request)
    {
        try {
            $user = $this->accessKeyService->authenticateKey($request);
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'access_key', false, 'Invalid key');
                throw new \RuntimeException('Invalid API key', 401);
            }

            $this->accessTokenService->logLogin($user->id, $request, 'access_key', true);
            $token = $this->accessTokenService->generateToken($user, $request);

            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'user' => $user
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'access_key', false, $e->getMessage());
            Log::error("Key auth error: {$e->getMessage()}");
            return response()->json(['error' => 'Authentication failed'], 500);
        }
    }

    /**
     * Revoke API key
     */
    public function revokeAccessKey(Request $request, $keyId)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Unauthorized');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $result = $this->accessKeyService->revokeKey($keyId, $user->id);
            if (!$result) {
                throw new \RuntimeException('Key not found', 404);
            }

            return response()->json(['message' => 'Key revoked']);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            Log::error("Revoke key error: {$e->getMessage()}");
            return response()->json(['error' => 'Revocation failed'], 500);
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
