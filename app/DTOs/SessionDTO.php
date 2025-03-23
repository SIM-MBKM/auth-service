<?php

namespace App\DTOs;

use Illuminate\Http\Request;

class SessionDTO
{
    public function __construct(
        public readonly string $user_id,
        public readonly string $token_hash,
        public readonly string $user_agent,
        public readonly string $ip_address,
        public readonly int $expires_at
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            user_id: $request->validate(['user_id' => 'required|uuid'])['user_id'],
            token_hash: $request->validate(['token_hash' => 'required|string'])['token_hash'],
            user_agent: $request->userAgent(),
            ip_address: $request->ip(),
            expires_at: $request->validate(['expires_at' => 'required|integer'])['expires_at']
        );
    }
}
