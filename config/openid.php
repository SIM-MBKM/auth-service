<?php

return [
    'provider' => env('WORKOS_ISSUER', 'https://api.workos.com/oidc'),
    'client_id' => env('WORKOS_CLIENT_ID'),
    'client_secret' => env('WORKOS_CLIENT_SECRET'),
    'redirect_uri' => env('WORKOS_REDIRECT_URI'),
    'post_logout_redirect_uri' => env('WORKOS_LOGOUT_REDIRECT_URI'),
    'scope' => 'openid email profile',
];