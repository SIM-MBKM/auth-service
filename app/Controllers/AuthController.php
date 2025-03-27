<?php

namespace App\Controllers;

use App\DTOs\APIKeyCreateDTO;
use App\DTOs\UserDTO;
use App\Models\User;
use App\Models\UserIdentity;
use App\Repositories\UserRepository;
use App\Services\AccessTokenService;
use App\Services\APIKeyService;
use App\Services\SocialiteService;
use Exception;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    protected $accessTokenService;
    protected $apiKeyService;
    protected $userRepository;
    protected $socialiteService;

    public function __construct(
        AccessTokenService $accessTokenService,
        APIKeyService $apiKeyService,
        SocialiteService $socialiteService,
        UserRepository $userRepository
    ) {
        $this->accessTokenService = $accessTokenService;
        $this->apiKeyService = $apiKeyService;
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
     * Validate JWT Token
     */
    public function validateToken(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->input('token'));

            return response()->json([
                'success' => true,
                'data' => $user
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
     * Generate API key
     */
    public function generateAPIKey(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Invalid credentials');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $dto = APIKeyCreateDTO::fromRequest($request);
            $payload = $this->apiKeyService->createAPIKey($dto, $user->id);

            return response()->json([
                'api_key' => $payload['plain_text_key'],
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
    public function listAPIKeys(Request $request)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Unauthorized');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $keys = $this->apiKeyService->listUserKeys($user->id);

            return response()->json([
                'api_keys' => $keys->map(fn($key) => [
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
            $user = $this->apiKeyService->authenticateKey($request);
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Invalid key');
                throw new \RuntimeException('Invalid API key', 401);
            }

            $this->accessTokenService->logLogin($user->id, $request, 'api_key', true);
            $token = $this->accessTokenService->generateToken($user, $request);

            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'user' => $user
            ]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], $e->getCode());
        } catch (\Exception $e) {
            $this->accessTokenService->logLogin(null, $request, 'api_key', false, $e->getMessage());
            Log::error("Key auth error: {$e->getMessage()}");
            return response()->json(['error' => 'Authentication failed'], 500);
        }
    }

    /**
     * Revoke API key
     */
    public function revokeAPIKey(Request $request, $keyId)
    {
        try {
            $user = $this->accessTokenService->getUserFromToken($request->bearerToken());
            if (!$user) {
                $this->accessTokenService->logLogin(null, $request, 'api_key', false, 'Unauthorized');
                throw new \RuntimeException('Unauthorized', 401);
            }

            $result = $this->apiKeyService->revokeKey($keyId, $user->id);
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
