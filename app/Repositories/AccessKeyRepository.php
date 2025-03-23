<?php

namespace App\Repositories;

use App\Models\AccessKey;
use Illuminate\Database\Eloquent\Collection;

class AccessKeyRepository
{
    public function create(array $data)
    {
        return AccessKey::create($data);
    }

    public function update(string $accessKeyId, array $data)
    {
        return AccessKey::where('id', $accessKeyId)->update($data);
    }

    public function findUserKey(string $accessKeyId, string $userId): ?AccessKey
    {
        return AccessKey::where('id', $accessKeyId)
            ->where('user_id', $userId)
            ->first();
    }

    public function findUserKeysByUserId(string $userId): ?Collection
    {
        return AccessKey::where('user_id', $userId)
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

    public function findActiveKeyByKeyHash(string $keyHash): ?AccessKey
    {
        return AccessKey::where('key_hash', $keyHash)
            ->where('is_active', true)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->first();
    }
}
