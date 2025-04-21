<?php

namespace App\Controllers;

use Illuminate\Routing\Controller;

class BaseController
{
    protected function successResponse($data, string $message = "success", int $statusCode = 200)
    {
        return response()->json(
            [
                'status' => 'success',
                'message' => $message,
                'data' => $data,
            ],
            $statusCode
        );
    }

    protected function errorResponse(string $message = 'error', int $statusCode = 400, $errors = null)
    {
        $response = [
            'status' => 'failed',
            'message' => $message,
        ];

        if (!is_null($errors)) {
            $response['errors'] = $errors;
        }

        return response()->json($response, $statusCode);
    }
}
