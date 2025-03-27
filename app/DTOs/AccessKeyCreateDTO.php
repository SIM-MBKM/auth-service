<?php

namespace App\DTOs;

use Illuminate\Http\Request;;

class APIKeyCreateDTO
{
    public function __construct(
        public readonly string $description,
        public readonly ?array $scopes,
        public readonly ?string $expires_at,
        public readonly ?bool $is_active
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            description: $request->validate(['description' => 'required|string|max:255'])['description'],
            scopes: $request->validate(['scopes' => 'nullable|array'])['scopes'],
            expires_at: $request->validate(['expires_at' => 'nullable|date|after:now'])['expires_at'],
            is_active: $request->validate(['is_active' => 'sometimes|boolean'])['is_active'] ?? true
        );
    }
}
