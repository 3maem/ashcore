<?php

use App\Http\Controllers\AshController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| ASH Protected API Routes
|--------------------------------------------------------------------------
|
| These routes demonstrate ASH integration with Laravel.
|
*/

// Context issuance (no ASH protection needed)
Route::get('/context', [AshController::class, 'issueContext']);

// Public endpoint (no protection)
Route::get('/public', [AshController::class, 'publicEndpoint']);

// Protected endpoints (require ASH middleware)
Route::middleware(['ash'])->group(function () {
    Route::post('/update', [AshController::class, 'update']);
    Route::put('/profile', [AshController::class, 'updateProfile']);
});

// Health check
Route::get('/health', [AshController::class, 'health']);
