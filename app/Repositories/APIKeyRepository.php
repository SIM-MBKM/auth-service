<?php

namespace App\Repositories;

use App\Models\APIKey;
use Illuminate\Database\Eloquent\Collection;

class APIKeyRepository
{
    public function create(array $data)
    {
        return APIKey::create($data);
    }

    public function update(string $apiKeyId, array $data)
    {
        return APIKey::where('id', $apiKeyId)->update($data);
    }

    public function findUserKey(string $apiKeyId, string $userId): ?APIKey
    {
        return APIKey::where('id', $apiKeyId)
            ->where('user_id', $userId)
            ->first();
    }

    public function findUserKeysByUserId(string $userId): ?Collection
    {
        return APIKey::where('user_id', $userId)
            ->select(
                'id',
                'description',
                'expires_at',
                'scopes',
                'last_used_at',
                'is_active',
                'created_at',
                'updated_at'
            )
            ->get();
    }

    public function findActiveKeyByKeyHash(string $keyHash): ?APIKey
    {
        return APIKey::where('key_hash', $keyHash)
            ->where('is_active', true)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->first();
    }
}
