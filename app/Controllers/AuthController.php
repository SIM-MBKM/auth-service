<?php

namespace App\Controllers;

use App\Models\User;
use App\Models\UserIdentity;
use App\Models\AccessKey;
use App\Services\AuthService;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    protected $authService;
    
    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
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

            // Find or create user identity
            $userIdentity = UserIdentity::firstOrNew([
                'provider' => 'google',
                'provider_user_id' => $googleUser->getId(),
            ]);
            
            if (!$userIdentity->exists) {
                // Check if user already exists with this email
                $user = User::where('email', $googleUser->getEmail())->first();
                
                if (!$user) {
                    // Create new user
                    $user = User::create([
                        'email' => $googleUser->getEmail(),
                        'name' => $googleUser->getName(),
                        'role' => 'user',
                    ]);
                }
                
                // Create new identity
                $userIdentity->user_id = $user->id;
                $userIdentity->provider_data = json_encode([
                    'name' => $googleUser->getName(),
                    'email' => $googleUser->getEmail(),
                    'avatar' => $googleUser->getAvatar(),
                ]);
            } else {
                $user = User::find($userIdentity->user_id);
                
                // Update identity data
                $userIdentity->provider_data = json_encode([
                    'name' => $googleUser->getName(),
                    'email' => $googleUser->getEmail(),
                    'avatar' => $googleUser->getAvatar(),
                ]);
            }
            
            // Update tokens
            $userIdentity->access_token = $googleUser->token;
            $userIdentity->refresh_token = $googleUser->refreshToken ?? null;
            $userIdentity->expires_at = $googleUser->expiresIn ? now()->addSeconds($googleUser->expiresIn) : null;
            $userIdentity->save();
            
            Log::info("halo", $userIdentity);
            // Log successful login
            $this->authService->logLogin($user->id, $request, 'google', true);
            
            // Generate JWT
            $token = $this->authService->generateToken($user, $request);
            
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'user' => $user
            ]);
            
        } catch (\Exception $e) {
            Log::error('Google authentication failed: ' . $e->getMessage());
            
            // Log the error
            $this->authService->logLogin(null, $request, 'google', false, $e->getMessage());
            
            return response()->json([
                'error' => 'Authentication failed',
                'message' => $e->getMessage()
            ], 401);
        }
    }
    
    /**
     * Generate API key for a user
     */
    public function generateAccessKey(Request $request)
    {
        $request->validate([
            'description' => 'required|string|max:255',
            'expires_at' => 'nullable|date|after:now',
            'scopes' => 'nullable|array',
        ]);
        
        $user = $this->authService->getUserFromToken($request->bearerToken());
        
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        // Generate a secure random key
        $plainTextKey = bin2hex(random_bytes(24));  
        
        // Store hashed version in database
        $accessKey = new AccessKey();
        $accessKey->user_id = $user->id;
        $accessKey->key_hash = hash('sha256', $plainTextKey);
        $accessKey->description = $request->description;
        $accessKey->expires_at = $request->expires_at;
        $accessKey->scopes = json_encode($request->scopes ?? []);
        $accessKey->last_used_at = null;
        $accessKey->is_active = true;
        $accessKey->save();
        
        // Return the plain text key - it won't be retrievable after this
        return response()->json([
            'access_key' => $plainTextKey,
            'key_id' => $accessKey->id,
            'description' => $accessKey->description,
            'expires_at' => $accessKey->expires_at,
            'scopes' => json_decode($accessKey->scopes),
            'created_at' => $accessKey->created_at
        ]);
    }
    
    /**
     * List all access keys for the current user
     */
    public function listAccessKeys(Request $request)
    {
        $user = $this->authService->getUserFromToken($request->bearerToken());
        
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $keys = AccessKey::where('user_id', $user->id)
            ->select('id', 'description', 'expires_at', 'scopes', 'last_used_at', 'is_active', 'created_at', 'updated_at')
            ->get();
            
        return response()->json([
            'access_keys' => $keys->map(function($key) {
                $key->scopes = json_decode($key->scopes);
                return $key;
            })
        ]);
    }
    
    /**
     * Authenticate with access key
     */
    public function authenticateWithKey(Request $request)
    {
        $accessKeyHeader = $request->header('X-API-Key');
        if (!$accessKeyHeader) {
            return response()->json(['error' => 'API key required'], 401);
        }
        
        $keyHash = hash('sha256', $accessKeyHeader);
        $accessKey = AccessKey::where('key_hash', $keyHash)
            ->where('is_active', true)
            ->where(function($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->first();
            
        if (!$accessKey) {
            $this->authService->logLogin(null, $request, 'access_key', false, 'Invalid API key');
            return response()->json(['error' => 'Invalid or expired API key'], 401);
        }
        
        // Update last used timestamp
        $accessKey->last_used_at = now();
        $accessKey->save();
        
        // Get the user associated with this key
        $user = User::find($accessKey->user_id);
        
        if (!$user) {
            $this->authService->logLogin(null, $request, 'access_key', false, 'User not found');
            return response()->json(['error' => 'User not found'], 401);
        }
        
        // Log successful login
        $this->authService->logLogin($user->id, $request, 'access_key', true);
        
        // Generate JWT for this user
        $token = $this->authService->generateToken($user, $request);
        
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'user' => $user,
            'scopes' => json_decode($accessKey->scopes),
        ]);
    }
    
    /**
     * Revoke API key
     */
    public function revokeAccessKey(Request $request, $keyId)
    {
        $user = $this->authService->getUserFromToken($request->bearerToken());
        
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        $accessKey = AccessKey::where('id', $keyId)
            ->where('user_id', $user->id)
            ->first();
            
        if (!$accessKey) {
            return response()->json(['error' => 'Key not found'], 404);
        }
        
        $accessKey->is_active = false;
        $accessKey->save();
        
        return response()->json(['message' => 'Key revoked successfully']);
    }
    
    /**
     * Logout (revoke token)
     */
    public function logout(Request $request)
    {
        $token = $request->bearerToken();
        
        if (!$token) {
            return response()->json(['error' => 'No token provided'], 400);
        }
        
        $success = $this->authService->deleteToken($token);
        
        if ($success) {
            return response()->json(['message' => 'Logged out successfully']);
        } else {
            return response()->json(['error' => 'Logout failed'], 500);
        }
    }
    
    /**
     * Get current user
     */
    public function getUser(Request $request)
    {
        $user = $this->authService->getUserFromToken($request->bearerToken());
        
        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
        // Get connected identities
        $identities = UserIdentity::where('user_id', $user->id)
            ->select('provider', 'provider_user_id', 'updated_at')
            ->get();
        
        return response()->json([
            'user' => $user,
            'identities' => $identities
        ]);
    }
    
    /**
     * Refresh token
     */
    public function refreshToken(Request $request)
    {
        $token = $request->bearerToken();
        
        if (!$token) {
            return response()->json(['error' => 'No token provided'], 400);
        }
        
        $user = $this->authService->getUserFromToken($token);
        
        if (!$user) {
            return response()->json(['error' => 'Invalid or expired token'], 401);
        }
        
        // Revoke old token
        $this->authService->deleteToken($token);
        
        // Generate new token
        $newToken = $this->authService->generateToken($user, $request);
        
        return response()->json([
            'access_token' => $newToken,
            'token_type' => 'bearer',
            'user' => $user
        ]);
    }
}