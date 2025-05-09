<?php

namespace App\Repositories;

use App\DTOs\UserDTO;
use App\Models\User;

class UserRepository
{
    public function createUser(UserDTO $dto): User
    {
        return User::create([
            'name' => $dto->name,
            'email' => $dto->email,
            'sso_id' => $dto->sso_id
        ]);
    }

    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }

    /**
     * legacy support
     */
    public function findByRememberToken($token): ?User
    {
        return User::where('remember_token', $token)->first();
    }

    public function findByUserId(string $userId): User
    {
        return User::find($userId);
    }
}
