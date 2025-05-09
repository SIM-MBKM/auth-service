<?php

namespace App\DTOs;

use Illuminate\Http\Request;
use Laravel\Socialite\Contracts\User as SocialiteUser;

class UserDTO
{
    public function __construct(
        public readonly string $name,
        public readonly string $email,
        public readonly ?string $sso_id
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            name: $request->validate(['name' => 'required|string|max:255'])['name'],
            email: $request->validate(['email' => 'required|email|unique:users,email'])['email'],
            sso_id: $request->validate(['sso_id' => 'nullable|string'])['sso_id'],
        );
    }

    public static function fromSocialite(SocialiteUser $user): self
    {
        return new self(
            name: $user->getName(),
            email: $user->getEmail(),
            sso_id: $user->getId()
        );
    }
}
