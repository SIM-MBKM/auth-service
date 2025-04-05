<?php

namespace App\Services;

use App\Models\LoginHistory;
use App\Models\Session;
use App\Models\User;
use App\Repositories\LoginHistoryRepository;
use App\Repositories\SessionRepository;
use App\Repositories\UserIdentityRepository;
use App\Repositories\UserRepository;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;

class AccessTokenService
{
    protected $jwtSecret;
    protected $jwtExpiry;

    public function __construct(
        private SessionRepository $sessionRepository,
        private UserRepository $userRepository,
        private LoginHistoryRepository $loginHistoryRepository,
        private UserIdentityRepository $userIdentityRepository,
    ) {
        $this->jwtSecret = config('jwt.jwt_secret');
        $this->jwtExpiry = (int) config('jwt.jwt_expiry');
        $this->sessionRepository = $sessionRepository;
        $this->userRepository = $userRepository;
        $this->loginHistoryRepository = $loginHistoryRepository;
        $this->userIdentityRepository = $userIdentityRepository;
    }

    public function generateToken($user, Request $request): string
    {
        try {
            $payload = [
                'iss' => config('jwt.jwt_issuer'),
                'sub' => [
                    'id' => $user->id,
                    'email' => $user->email,
                ],
                'iat' => time(),
                'exp' => time() + $this->jwtExpiry
            ];

            $token = JWT::encode($payload, $this->jwtSecret, 'HS256');
            $this->recordSession($user, $token, $request);

            return $token;
        } catch (\Exception $e) {
            Log::error('Token generation failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to generate authentication token', 500, $e);
        }
    }

    protected function recordSession($user, $token, Request $request): void
    {
        try {
            $tokenHash = hash('sha256', $token);
            $existingSession = $this->sessionRepository->sessionExist($request, $user);

            if ($existingSession) {
                $this->updateExistingSession($existingSession, $token, $tokenHash);
            } else {
                $this->createNewSession($user, $token, $tokenHash, $request);
            }
        } catch (\Exception $e) {
            Log::error('Session recording failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to record session', 500, $e);
        }
    }

    private function updateExistingSession(Session $session, string $token, string $tokenHash): void
    {
        try {
            $payload = unserialize($session->payload);
            $payload['jwt_token'] = $token;
            $payload['jwt_token_hash'] = $tokenHash;

            $session->payload = serialize($payload);
            $session->token_hash = $tokenHash;
            $session->expires_at = now()->addSeconds($this->jwtExpiry);
            $session->last_activity = now()->timestamp;

            $this->sessionRepository->saveSession($session);
        } catch (\Exception $e) {
            throw new RuntimeException('Session update failed', 500, $e);
        }
    }

    private function createNewSession($user, string $token, string $tokenHash, Request $request): void
    {
        try {
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
                'jwt_token' => $token,
                'jwt_token_hash' => $tokenHash,
            ];
            $session->payload = serialize($payload);

            $this->sessionRepository->saveSession($session);
        } catch (\Exception $e) {
            throw new RuntimeException('Session creation failed', 500, $e);
        }
    }

    public function validateToken($token)
    {
        try {
            // dd($token)
            $tokenHash = hash('sha256', $token);
            $user = $this->userRepository->findByRememberToken($tokenHash);

            if (!$user) {
                $session = $this->sessionRepository->findValidSessionByTokenHash($tokenHash);
                if (!$session) {
                    throw new RuntimeException('Invalid token', 401);
                }
                $user = $this->userRepository->findByUserId($session->user_id);
            }

            if (!$user) {
                throw new RuntimeException('User not found', 404);
            }

            $credentials = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
            $this->sessionRepository->updateLastActivity($tokenHash, now()->timestamp);

            return $credentials;
        } catch (ExpiredException $e) {
            throw new RuntimeException('Token expired', 401, $e);
        } catch (SignatureInvalidException $e) {
            throw new RuntimeException('Invalid token signature', 401, $e);
        } catch (\Exception $e) {
            Log::error('Token validation failed: ' . $e->getMessage());
            throw new RuntimeException('Invalid authentication token', 401, $e);
        }
    }

    public function getUserFromToken($token): ?User
    {
        try {
            $credentials = $this->validateToken($token);

            if (!$credentials || !isset($credentials->sub->email)) {
                return null;
            }

            return $this->userRepository->findByEmail($credentials->sub->email);
        } catch (\Exception $e) {
            Log::error('User retrieval from token failed: ' . $e->getMessage());
            return null;
        }
    }

    public function getIdentities($userId)
    {
        try {
            return $this->userIdentityRepository->findIdentitiesByUserId($userId);
        } catch (\Exception $e) {
            Log::error('Identity retrieval failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to retrieve user identities', 500, $e);
        }
    }

    public function deleteToken($token): bool
    {
        try {
            $tokenHash = hash('sha256', $token);
            $user = $this->userRepository->findByRememberToken($token);

            if ($user) {
                $user->remember_token = null;
                $user->save();
            }

            return $this->sessionRepository->deleteSessionByTokenHash($tokenHash);
        } catch (\Exception $e) {
            Log::error('Token deletion failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to delete token', 500, $e);
        }
    }

    public function logLogin($userId, Request $request, $method, $success, $failureReason = null): void
    {
        try {
            if (is_null($userId)) {
                Log::warning('Attempted to log login without user ID', [
                    'method' => $method,
                    'ip' => $request->ip()
                ]);
                return;
            }

            $this->loginHistoryRepository->createLoginHistory(
                $userId,
                $method,
                $request->ip(),
                $request->userAgent(),
                $success,
                $failureReason
            );
        } catch (\Exception $e) {
            Log::error('Login history recording failed: ' . $e->getMessage());
        }
    }
}
