<?php

namespace App\Services;

use App\DTOs\APIKeyCreateDTO;
use App\Repositories\APIKeyRepository;
use App\Repositories\UserRepository;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class APIKeyService
{
    public function __construct(
        private APIKeyRepository $apiKeyRepository,
        private UserRepository $userRepository
    ) {}

    public function createAPIKey(APIKeyCreateDTO $dto, string $userId): array
    {
        try {
            $user = $this->userRepository->findByUserId($userId);
            if (!$user) {
                throw new RuntimeException('User not found', 404);
            }

            $plainTextKey = bin2hex(random_bytes(24));
            if (empty($plainTextKey)) {
                throw new RuntimeException('Failed to generate secure key', 500);
            }

            $apiKey = $this->apiKeyRepository->create([
                'user_id' => $user->id,
                'key_hash' => hash('sha256', $plainTextKey),
                'description' => $dto->description,
                'scopes' => $dto->scopes,
                'expires_at' => $dto->expires_at,
                'is_active' => true
            ]);

            $apiKeyDetails = $apiKey->toArray();
            unset($apiKeyDetails['key_hash']);

            return [
                'plain_text_key' => $plainTextKey,
                'details' => $apiKeyDetails
            ];
        } catch (QueryException $e) {
            if ($e->errorInfo[1] === 1062) { // MySQL duplicate entry
                throw new RuntimeException('Access key already exists', 409);
            }
            Log::error('Database error creating access key: ' . $e->getMessage());
            throw new RuntimeException('Failed to create access key', 500, $e);
        } catch (\Exception $e) {
            Log::error('Unexpected error creating access key: ' . $e->getMessage());
            throw new RuntimeException('Failed to create access key', 500, $e);
        }
    }

    public function authenticateKey(Request $request)
    {
        $apiKeyHeader = $request->header('X-API-Key');
        if (!$apiKeyHeader) {
            throw new RuntimeException('API key required', 401);
        }

        $keyHash = hash('sha256', $apiKeyHeader);
        $apiKey = $this->apiKeyRepository->findActiveKeyByKeyHash($keyHash);

        if (!$apiKey) {
            throw new RuntimeException('Invalid API key', 401);
        }

        try {
            $this->apiKeyRepository->update($apiKey->id, ['last_used_at' => now()]);
            return $this->userRepository->findByUserId($apiKey->user_id);
        } catch (\Exception $e) {
            Log::error('Key authentication error: ' . $e->getMessage());
            throw new RuntimeException('Failed to authenticate with key', 500, $e);
        }
    }

    public function revokeKey(string $apiKeyId, string $userId): bool
    {
        try {
            $key = $this->apiKeyRepository->findUserKey($apiKeyId, $userId);

            if (!$key) {
                throw new ModelNotFoundException();
            }

            $updated = $this->apiKeyRepository->update($apiKeyId, ['is_active' => false]);

            if (!$updated) {
                throw new RuntimeException('Failed to revoke key', 500);
            }

            return true;
        } catch (ModelNotFoundException $e) {
            throw new RuntimeException('Access key not found', 404, $e);
        } catch (\Exception $e) {
            Log::error('Key revocation error: ' . $e->getMessage());
            throw new RuntimeException('Failed to revoke access key', 500, $e);
        }
    }

    public function listUserKeys(string $userId)
    {
        try {
            return $this->apiKeyRepository->findUserKeysByUserId($userId);
        } catch (\Exception $e) {
            Log::error('List keys error: ' . $e->getMessage());
            throw new RuntimeException('Failed to retrieve access keys', 500, $e);
        }
    }
}
