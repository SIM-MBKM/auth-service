<?php

namespace App\DTOs;

use Illuminate\Http\Request;

class LoginHistoryDTO
{
    public function __construct(
        public readonly string $user_id,
        public readonly string $auth_method,
        public readonly string $ip_address,
        public readonly string $user_agent,
        public readonly bool $success,
        public readonly ?string $failure_reason
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            user_id: $request->validate(['user_id' => 'required|uuid'])['user_id'],
            auth_method: $request->validate(['auth_method' => 'required|string'])['auth_method'],
            ip_address: $request->ip(),
            user_agent: $request->userAgent(),
            success: $request->validate(['success' => 'required|boolean'])['success'] ?? false,
            failure_reason: $request->validate(['failure_reason' => 'nullable|string'])['failure_reason'] ?? null
        );
    }
}
