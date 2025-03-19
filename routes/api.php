<?php

use Illuminate\Support\Facades\Route;
use App\Controllers\AuthController;

// Social Authentication (Google)
Route::get('/auth/google/redirect', [AuthController::class, 'redirectToGoogle']);
Route::get('/auth/google/callback', [AuthController::class, 'handleGoogleCallback']);

// API Key Management
Route::post('/auth/access-keys', [AuthController::class, 'generateAccessKey']);
Route::get('/auth/access-keys', [AuthController::class, 'listAccessKeys']);
Route::post('/auth/access-keys/authenticate', [AuthController::class, 'authenticateWithKey']);
Route::delete('/auth/access-keys/{keyId}', [AuthController::class, 'revokeAccessKey']);

// JWT Token Actions
Route::post('/auth/refresh', [AuthController::class, 'refreshToken']);
Route::post('/auth/logout', [AuthController::class, 'logout']);

// Get current user details
Route::get('/auth/user', [AuthController::class, 'getUser']);
