<?php

namespace App\Providers;

use Illuminate\Http\Client\Request;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;

//TODO:
// class OpenIDProvider extends AbstractProvider implements ProviderInterface
// {
//     protected $scopes;

//     public function __construct(Request $request, $clientId, $clientSecret, $redirectUri, array $guzzle = [])
//     {
//         parent::__construct($request, $clientId, $clientSecret, $redirectUri, $guzzle);
//         $this->scopes = config('openid.scope');
//     }


// }