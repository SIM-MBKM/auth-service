<?php

namespace App\Repositories;

use App\Models\UserIdentity;
use Illuminate\Database\Eloquent\Collection;

class UserIdentityRepository
{
    public function findOrNewIdentity(string $provider, string $providerId): UserIdentity
    {
        return UserIdentity::firstOrNew([
            'provider' => $provider,
            'provider_user_id' => $providerId
        ]);
    }

    public function updateIdentityTokens(UserIdentity $identity, string $token, ?string $refreshToken, ?int $expiresIn): void
    {
        $identity->access_token = $token;
        $identity->refresh_token = $refreshToken;
        $identity->expires_at = $expiresIn ? now()->addSeconds($expiresIn) : null;
        $identity->save();
    }

    public function findIdentitiesByUserId(string $userId): Collection
    {
        return UserIdentity::where('user_id', $userId)
            ->select('provider', 'provider_user_id', 'updated_at')
            ->get();
    }
}
