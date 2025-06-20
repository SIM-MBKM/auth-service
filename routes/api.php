<?php

use Illuminate\Support\Facades\Route;
use App\Controllers\AuthController;

// Social Authentication (Google)
Route::get('/v1/auth/google/redirect', [AuthController::class, 'redirectToGoogle']);
Route::get('/v1/auth/google/callback', [AuthController::class, 'handleGoogleCallback']);

// Social Authentication (SSO)
Route::get('/v1/auth/its/redirect', [AuthController::class, 'redirectToSSO']);
Route::get('/v1/auth/its/callback', [AuthController::class, 'handleSSOCallback']);
Route::post('/v1/auth/its/logout', [AuthController::class, 'logoutSSO']);

// API Key Management -- disabled, too much complexity
// Route::post('/auth/access-keys', [AuthController::class, 'generateAPIKey']); // Bearer Token
// Route::get('/auth/access-keys', [AuthController::class, 'listAPIKeys']); // X-API-Key
// Route::get('/auth/access-keys/scope', [AuthController::class, 'getAPIKeyScope']); // X-API-Key
// Route::post('/auth/access-keys/authenticate', [AuthController::class, 'authenticateWithKey']); // X-API-Key
// Route::delete('/auth/access-keys/{keyId}', [AuthController::class, 'revokeAPIKey']); // X-API-Key

// JWT Token Actions
Route::post('/v1/auth/refresh', [AuthController::class, 'refreshToken']);
Route::post('/v1/auth/logout', [AuthController::class, 'logout']);
Route::post('/v1/auth/validate-token', [AuthController::class, 'validateToken']);

// Get current user details
Route::get('/v1/auth/user', [AuthController::class, 'getUser']);

// Check Identity Provider
Route::get('/v1/auth/identity/{email}', [AuthController::class, 'identityProviderCheck'])->where('email', '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}');