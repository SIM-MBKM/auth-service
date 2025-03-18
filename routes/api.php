<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Facades\Socialite;

Route::get('/auth/redirect', function () {
    $url = Socialite::driver('google')->redirect()->getTargetUrl();

    return response()->json(['url' => $url]);
});

Route::get('/auth/callback', function (Request $request) {
    $driver = Socialite::driver('google');
    $user = $driver->stateless()->user();

    // $authUser = \App\Models\User::updateOrCreate([
    //     'email' => $user->getEmail(),
    // ], [
    //     'name' => $user->getName(),
    //     'google_id' => $user->getId(),
    //     'avatar' => $user->getAvatar(),
    // ]);

    return response()->json($user);
});
