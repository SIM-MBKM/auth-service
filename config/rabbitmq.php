<?php

return [
    'connections' => [
        'user_sync' => [
            'host' => env('RABBITMQ_HOST'),
            'port' => env('RABBITMQ_PORT', 5672),
            'vhost' => 'user_sync',
            'user' => env('RABBITMQ_USER'),
            'password' => env('RABBITMQ_PASSWORD'),
        ],
    ],
];
