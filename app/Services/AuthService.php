<?php

namespace App\Services;

use App\Models\LoginHistory;
use App\Models\Session;
use App\Models\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuthService 
{
    protected $jwtSecret;
    protected $jwtExpiry;

    public function __construct()
    {
        $this->jwtSecret = env('jwt.jwt_secret');
        $this->jwtExpiry = config('jwt.jwt_expiry');
    }

    public function generateToken($user, Request $request)
    {
        $payload = [
            'iss' => config('jwt.jwt_issuer'),
            'sub' => [
                'id' => $user->id,
                'email' => $user->email,
                'role' => $user->role,
            ],
            'iat' => time(),
            'exp' => time() + $this->jwtExpiry
        ];
        
        $token = JWT::encode($payload, $this->jwtSecret, 'HS256');

        $user->remember_token = $token;
        $user->save();

        if ($request) {
            $this->recordSession($user, $token, $request);
        }

        return $token;
    }

    protected function recordSession($user, $token, Request $request)
    {
        $tokenHash = hash('sha256', $token);
        
        // First check if there's already a session for this user from Socialite
        $existingSession = Session::where('user_id', $user->id)
            ->where('user_agent', $request->userAgent())
            ->where('ip_address', $request->ip())
            ->latest('last_activity')
            ->first();
        
        if ($existingSession) {
            // Update existing session with your token data
            $payload = unserialize($existingSession->payload);
            $payload['jwt_token'] = $token;
            $payload['jwt_token_hash'] = $tokenHash;
            
            $existingSession->payload = serialize($payload);
            $existingSession->token_hash = $tokenHash;
            $existingSession->expires_at = now()->addSeconds($this->jwtExpiry);
            $existingSession->last_activity = now()->timestamp;
            $existingSession->save();
        } else {
            // Create new session
            $session = new Session();
            $session->id = Str::uuid()->toString();
            $session->user_id = $user->id;
            $session->token_hash = $tokenHash;
            $session->user_agent = $request->userAgent();
            $session->ip_address = $request->ip();
            $session->last_activity = now()->timestamp;
            $session->expires_at = now()->addSeconds($this->jwtExpiry);
            
            $payload = [
                'user_id' => $user->id,
                'email' => $user->email,
                'role' => $user->role,
                'jwt_token' => $token,
                'jwt_token_hash' => $tokenHash,
            ];
            $session->payload = serialize($payload);
            
            $session->save();
        }
        
        // Log the successful login
        $this->logLogin($user->id, $request, 'jwt', true);
    }

    public function validateToken($token)
    {
        try {
            $tokenHash = hash('sha256', $token);
            
            // Check if token exists in user's remember_token first (legacy support)
            $user = User::where('remember_token', $token)->first();
            if (!$user) {
                // Also check the sessions table by token hash
                $session = Session::where('token_hash', $tokenHash)
                    ->where('expires_at', '>', now())
                    ->first();
                
                if (!$session) {
                    return null;
                }
                
                $user = User::find($session->user_id);
                if (!$user) {
                    return null;
                }
            }
            
            // Decode and verify the token
            $credentials = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
            
            // Update session last activity
            Session::where('token_hash', $tokenHash)
                ->update(['last_activity' => now()->timestamp]);
                
            return $credentials;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function getUserFromToken($token)
    {
        $credentials = $this->validateToken($token);
        
        if ($credentials && isset($credentials->sub->email)) {
            $user = User::where('email', $credentials->sub->email)->first();
            return $user;
        }
        
        return null;
    }

    public function deleteToken($token): bool
    {
        try {
            $tokenHash = hash('sha256', $token);
            
            // Remove from user's remember_token (legacy support)
            $user = User::where('remember_token', $token)->first();
            if ($user) {
                $user->remember_token = null;
                $user->save();
            }
            
            // Remove from sessions table
            Session::where('token_hash', $tokenHash)->delete();
            
            return true;
        } catch(\Exception $e) {
            return false;
        }
    }

    public function logLogin($userId, Request $request, $method, $success, $failureReason = null)
    {
        LoginHistory::create([
            'user_id' => $userId,
            'auth_method' => $method,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'success' => $success,
            'failure_reason' => $failureReason
        ]);
    }
}