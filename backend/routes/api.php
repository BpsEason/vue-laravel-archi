<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Admin\AuthController as AdminAuthController;
use App\Http\Controllers\Api\Client\AuthController as ClientAuthController;
use App\Http\Controllers\Api\Admin\ImageController as AdminImageController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// 後台管理員 API 路由
// Nginx 已經處理了 /api/ 前綴
Route::group(['prefix' => 'admin', 'middleware' => []], function () {
    // 登入不需要 token
    Route::post('/login', [AdminAuthController::class, 'login']);
    
    // 以下路由需要 JWT 認證和速率限制
    Route::group(['middleware' => ['auth:admin', 'throttle:60,1']], function () {
        Route::post('/logout', [AdminAuthController::class, 'logout']);
        Route::post('/refresh', [AdminAuthController::class, 'refresh']); // JWT 刷新
        Route::get('/user', [AdminAuthController::class, 'user']); // 獲取當前用戶資訊
        
        // 圖片上傳
        Route::post('/images/upload', [AdminImageController::class, 'upload']);
        // ... 其他管理員相關路由
    });
});

// 前台客戶端 API 路由
// Nginx 處理了 /api/ 前綴
Route::group(['prefix' => 'client', 'middleware' => ['throttle:60,1']], function () {
    Route::post('/login', [ClientAuthController::class, 'login']);

    Route::group(['middleware' => 'auth:client'], function () {
        Route::post('/logout', [ClientAuthController::class, 'logout']);
        Route->post('/refresh', [ClientAuthController::class, 'refresh']);
        Route::get('/user', [ClientAuthController::class, 'user']);
        // ... 其他客戶端相關路由
    });
});

// 如果有不需要任何前綴的通用 API，直接定義在這裡
// Route::get('/status', function() { return response()->json(['status' => 'ok']); });
