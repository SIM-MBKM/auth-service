<?php

namespace App\DTOs;

use Illuminate\Http\Request;
use Laravel\Socialite\Contracts\User as SocialiteUser;

class UserDTO
{
    public function __construct(
        public readonly string $name,
        public readonly string $email,
        public readonly ?string $sso_id,
        public readonly string $role,
        public readonly ?string $no_wa
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            name: $request->validate(['name' => 'required|string|max:255'])['name'],
            email: $request->validate(['email' => 'required|email|unique:users,email'])['email'],
            sso_id: $request->validate(['sso_id' => 'nullable|string'])['sso_id'],
            role: $request->validate(['role' => 'sometimes|string|in:user,admin'])['role'] ?? 'Mahasiswa',
            no_wa: $request->validate(['no_wa' => 'nullable|string|max:20'])['no_wa']
        );
    }

    public static function fromSocialite(SocialiteUser $user): self
    {
        return new self(
            name: $user->getName(),
            email: $user->getEmail(),
            sso_id: $user->getId(),
            role: 'Mahasiswa',
            no_wa: null
        );
    }
}
