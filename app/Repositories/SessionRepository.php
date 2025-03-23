<?php

namespace App\Repositories;

use App\Models\Session;
use Illuminate\Http\Request;

class SessionRepository
{
    public function sessionExist(Request $request, $user): ?Session
    {
        return Session::where('user_id', $user->id)
            ->where('user_agent', $request->userAgent())
            ->where('ip_address', $request->ip())
            ->latest('last_activity')
            ->first();
    }

    public function saveSession(Session $session): Session
    {
        $session->save();
        return $session;
    }

    public function findValidSessionByTokenHash(string $tokenHash): ?Session
    {
        return Session::where('token_hash', $tokenHash)
            ->where('expires_at', '>', now())
            ->first();
    }

    public function updateLastActivity(string $tokenHash, int $timestamp): int
    {
        return Session::where('token_hash', $tokenHash)
            ->update(['last_activity' => $timestamp]);
    }

    public function deleteSessionbyTokenHash(string $tokenHash): bool
    {
        return Session::where('token_hash', $tokenHash)->delete();
    }
}
