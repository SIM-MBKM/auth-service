<?php

namespace App\Services;

use App\DTOs\AccessKeyCreateDTO;
use App\Models\AccessKey;
use App\Repositories\AccessKeyRepository;
use App\Repositories\UserRepository;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class AccessKeyService
{
    public function __construct(
        private AccessKeyRepository $accessKeyRepository,
        private UserRepository $userRepository
    ) {}

    public function createAccessKey(AccessKeyCreateDTO $dto, string $userId): array
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

            $accessKey = $this->accessKeyRepository->create([
                'user_id' => $user->id,
                'key_hash' => hash('sha256', $plainTextKey),
                'description' => $dto->description,
                'scopes' => $dto->scopes,
                'expires_at' => $dto->expires_at,
                'is_active' => true
            ]);

            $accessKeyDetails = $accessKey->toArray();
            unset($accessKeyDetails['key_hash']);

            return [
                'plain_text_key' => $plainTextKey,
                'details' => $accessKeyDetails
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
        $accessKeyHeader = $request->header('X-API-Key');
        if (!$accessKeyHeader) {
            throw new RuntimeException('API key required', 401);
        }

        $keyHash = hash('sha256', $accessKeyHeader);
        $accessKey = $this->accessKeyRepository->findActiveKeyByKeyHash($keyHash);

        if (!$accessKey) {
            throw new RuntimeException('Invalid API key', 401);
        }

        try {
            $this->accessKeyRepository->update($accessKey->id, ['last_used_at' => now()]);
            return $this->userRepository->findByUserId($accessKey->user_id);
        } catch (\Exception $e) {
            Log::error('Key authentication error: ' . $e->getMessage());
            throw new RuntimeException('Failed to authenticate with key', 500, $e);
        }
    }

    public function revokeKey(string $accessKeyId, string $userId): bool
    {
        try {
            $key = $this->accessKeyRepository->findUserKey($accessKeyId, $userId);

            if (!$key) {
                throw new ModelNotFoundException();
            }

            $updated = $this->accessKeyRepository->update($accessKeyId, ['is_active' => false]);

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
            return $this->accessKeyRepository->findUserKeysByUserId($userId);
        } catch (\Exception $e) {
            Log::error('List keys error: ' . $e->getMessage());
            throw new RuntimeException('Failed to retrieve access keys', 500, $e);
        }
    }
}
