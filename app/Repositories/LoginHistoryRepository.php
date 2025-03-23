<?php

namespace App\Repositories;

use App\Models\LoginHistory;

class LoginHistoryRepository
{
    public function createLoginHistory(
        string $userId,
        string $authMethod,
        string $ipAddress,
        string $userAgent,
        bool $success,
        ?string $failureReason = null
    ) {
        return LoginHistory::create([
            'user_id'       => $userId,
            'auth_method'   => $authMethod,
            'ip_address'    => $ipAddress,
            'user_agent'    => $userAgent,
            'success'       => $success,
            'failure_reason' => $failureReason,
        ]);
    }
}
