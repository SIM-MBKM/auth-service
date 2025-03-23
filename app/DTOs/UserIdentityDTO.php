<?php

namespace App\DTOs;

use Illuminate\Http\Request;

class UserIdentityDTO
{
    public function __construct(
        public readonly string $user_id,
        public readonly string $provider,
        public readonly string $provider_user_id,
        public readonly string $access_token,
        public readonly ?string $refresh_token,
        public readonly ?string $expires_at,
        public readonly array $provider_data
    ) {}

    public static function fromRequest(Request $request)
    {
        return new self(
            user_id: $request->validate(['user_id' => 'required|uuid'])['user_id'],
            provider: $request->validate(['provider' => 'required|in:google,sso'])['provider'],
            provider_user_id: $request->validate(['provider_user_id' => 'required|string'])['provider_user_id'],
            access_token: $request->validate(['access_token' => 'required|string'])['access_token'],
            refresh_token: $request->validate(['refresh_token' => 'nullable|string'])['refresh_token'],
            expires_at: $request->validate(['expires_at' => 'nullable|date'])['expires_at'],
            provider_data: $request->validate(['provider_data' => 'required|array'])['provider_data']
        );
    }
}
