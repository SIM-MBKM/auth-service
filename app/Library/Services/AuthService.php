<?php

namespace App\Libraries\Services;

use Illuminate\Support\Facades\Http;
use SimMbkm\ModService\Service as BaseService;

class AuthService extends BaseService
{
    public function post($endpoint, $data)
    {
        $baseUri = config('services.auth_service.base_uri');

        if ($endpoint === 'api/v1/auth/validate-token') {
            $response = Http::timeout(15)
                ->post($baseUri . '/auth/validate-token', [
                    'token' => $data['token']
                ]);

            return (object) [
                'success' => $response->successful(),
                'data' => $response->json()['data'] ?? null
            ];
        }

        throw new \Exception("Unknown auth endpoint: {$endpoint}");
    }
}
