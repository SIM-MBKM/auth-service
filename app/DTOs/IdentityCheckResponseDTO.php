<?php

namespace App\DTOs;

class IdentityCheckResponseDTO
{
    public function __construct(
        public readonly string $email,
        public readonly bool $userExists,
        public readonly string $provider
    ) {
    }

    public function toArray(): array
    {
        return [
            'email' => $this->email,
            'user_exists' => $this->userExists,
            'provider' => $this->provider,
        ];
    }
}