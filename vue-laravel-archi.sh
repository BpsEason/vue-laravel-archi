#!/bin/bash

# 定義根目錄名稱
PROJECT_ROOT="vue-laravel-archi"

echo "正在建立專案根目錄: $PROJECT_ROOT"
mkdir -p "$PROJECT_ROOT"
cd "$PROJECT_ROOT" || { echo "無法進入 $PROJECT_ROOT 目錄，終止。"; exit 1; }

echo "正在建立 backend/ (Laravel) 目錄結構..."
# 修正後的 Laravel 核心目錄結構，只包含必要部分
mkdir -p backend/{app/{Http/Controllers/{Api/Admin,Api/Client},Models,Services,GrpcStubs},config,database/{migrations,factories,seeders},routes,storage/{app/public,logs,framework/cache,framework/sessions,framework/views},tests,public}
touch backend/.env
touch backend/composer.json
touch backend/routes/api.php
touch backend/app/Services/ImageService.php
touch backend/app/Http/Controllers/Api/Admin/AuthController.php
touch backend/app/Http/Controllers/Api/Client/AuthController.php
touch backend/app/Http/Controllers/Api/Admin/ImageController.php
touch backend/app/Models/User.php # 新增 User Model
touch backend/app/GrpcStubs/ImageWorkerClient.php # 佔位，實際由 protoc 生成

# 自動生成 User migration 檔案名稱
TIMESTAMP=$(date +%Y_%m_%d_%H%M%S)
touch backend/database/migrations/${TIMESTAMP}_create_users_table.php # 新增 User Migration

echo "正在建立 frontend-admin/ (Vue3) 目錄結構..."
# 前端只建立 src/stores、public 和 dist (dist 通常由構建生成)
mkdir -p frontend-admin/{src/stores,public,dist}
touch frontend-admin/package.json
touch frontend-admin/vite.config.js
touch frontend-admin/src/main.js
touch frontend-admin/src/App.vue
touch frontend-admin/src/stores/auth.js

echo "正在建立 docker/ 配置目錄結構..."
# Docker 配置目錄
mkdir -p docker/{nginx,php,frontend,grpc}
touch docker/nginx/default.conf
touch docker/php/Dockerfile
touch docker/frontend/Dockerfile
touch docker/grpc/Dockerfile

echo "正在建立 grpc-service/ 目錄結構..."
# gRPC 服務目錄
mkdir -p grpc-service/{proto,src/{Grpc/ImageProcessor,Services}}
touch grpc-service/proto/image.proto
touch grpc-service/src/Services/ImageProcessorImplementation.php
touch grpc-service/composer.json
touch grpc-service/server.php
touch grpc-service/.rr.yaml
touch grpc-service/src/support_laravel_facades.php # 引入 Laravel Facade 支援文件

echo "正在建立 docker-compose.yml 和 .gitignore..."
touch docker-compose.yml
touch .gitignore

echo "正在寫入配置檔案內容..."

# backend/.env 內容
cat << 'EOF' > backend/.env
APP_NAME=LaravelVueApp
APP_ENV=local
APP_KEY=base64:YOUR_APP_KEY_HERE # 執行 'php artisan key:generate' 後替換
APP_DEBUG=true
APP_URL=http://localhost

LOG_CHANNEL=stack
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=mysql # Docker 內部服務名稱
DB_PORT=3306
DB_DATABASE=laravel_vue_db
DB_USERNAME=laravel_user
DB_PASSWORD=laravel_password

REDIS_HOST=redis
REDIS_PASSWORD=null
REDIS_PORT=6379

BROADCAST_DRIVER=log
CACHE_DRIVER=redis
FILESYSTEM_DISK=public
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis
SESSION_LIFETIME=120

JWT_SECRET=YOUR_JWT_SECRET_HERE # 執行 'php artisan jwt:secret' 後替換

MAIL_MAILER=log
MAIL_HOST=mailpit
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

# 將 APP_URL 設為容器內 Laravel 的 URL (對內訪問)
APP_URL=http://localhost

# gRPC Image Worker Service
IMAGE_GRPC_HOST=image-worker
IMAGE_GRPC_PORT=50051
EOF

# backend/composer.json 內容 (新增 Laravel 必要依賴)
cat << 'EOF' > backend/composer.json
{
    "name": "laravel/laravel",
    "type": "project",
    "description": "A Laravel Vue Docker project.",
    "keywords": ["framework", "laravel", "vue", "docker", "grpc"],
    "license": "MIT",
    "require": {
        "php": "^8.2",
        "guzzlehttp/guzzle": "^7.2",
        "laravel/framework": "^10.0 || ^11.0",
        "laravel/sanctum": "^3.2",
        "laravel/tinker": "^2.8",
        "predis/predis": "^2.2",
        "tymon/jwt-auth": "^2.0",
        "spiral/roadrunner-grpc": "^2.10 || ^3.0",
        "google/protobuf": "^3.23",
        "grpc/grpc": "^1.40"
    },
    "require-dev": {
        "fakerphp/faker": "^1.9.1",
        "laravel/pint": "^1.0",
        "laravel/sail": "^1.18",
        "mockery/mockery": "^1.4.4",
        "nunomaduro/collision": "^7.0",
        "phpunit/phpunit": "^10.1",
        "spatie/laravel-ignition": "^2.0"
    },
    "autoload": {
        "psr-4": {
            "App\\": "app/",
            "Database\\Factories\\": "database/factories/",
            "Database\\Seeders\\": "database/seeders/",
            "App\\GrpcStubs\\": "app/GrpcStubs/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Tests\\": "tests/"
        }
    },
    "scripts": {
        "post-autoload-dump": [
            "Illuminate\\Foundation\\ComposerScripts::postAutoloadDump",
            "@php artisan package:discover --ansi"
        ],
        "post-update-cmd": [
            "@php artisan vendor:publish --tag=laravel-assets --ansi --force"
        ],
        "post-root-package-install": [
            "@php -r \"file_exists('.env') || copy('.env.example', '.env');\""
        ],
        "post-create-project-cmd": [
            "@php artisan key:generate --ansi"
        ]
    },
    "extra": {
        "laravel": {
            "dont-discover": []
        }
    },
    "config": {
        "optimize-autoloader": true,
        "preferred-install": "dist",
        "sort-packages": true,
        "allow-plugins": {
            "pestphp/pest-plugin": true,
            "php-http/discovery": true
        }
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
EOF

# backend/routes/api.php 內容 (不變)
cat << 'EOF' > backend/routes/api.php
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
EOF

# backend/app/Services/ImageService.php 內容 (改為呼叫 gRPC)
cat << 'EOF' > backend/app/Services/ImageService.php
<?php

namespace App\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use App\GrpcStubs\ImageProcessor\ImageRequest; // 假設由 protoc 生成
use App\GrpcStubs\ImageProcessor\ImageProcessorClient; // 假設由 protoc 生成

class ImageService {
    protected $grpcClient;

    public function __construct()
    {
        $grpcHost = env('IMAGE_GRPC_HOST', 'image-worker');
        $grpcPort = env('IMAGE_GRPC_PORT', '50051');
        $serverAddress = sprintf('%s:%s', $grpcHost, $grpcPort);

        // 注意：這裡使用 createInsecure() 是因為沒有 HTTPS，僅用於內部 Docker 網路通訊
        $this->grpcClient = new ImageProcessorClient($serverAddress, [
            'credentials' => \Grpc\ChannelCredentials::createInsecure(),
        ]);
    }

    /**
     * 將圖片上傳任務分發到 gRPC 服務。
     *
     * @param Request $request 包含上傳檔案的 HTTP 請求
     * @return string 返回圖片的公開 URL
     */
    public function processImageViaGrpc(Request $request): string {
        $request->validate(['image' => 'required|image|mimes:jpeg,png,jpg|max:2048']);
        $file = $request->file('image');

        $imageData = file_get_contents($file->getPathname());
        $filename = $file->getClientOriginalName();

        $grpcRequest = new ImageRequest();
        $grpcRequest->setImageData($imageData);
        $grpcRequest->setFilename($filename);

        try {
            list($response, $status) = $this->grpcClient->ProcessImage($grpcRequest)->wait();

            if ($status->code === \Grpc\STATUS_OK) {
                return $response->getImageUrl();
            } else {
                Log::error("gRPC Image Processing Failed: " . $status->details, ['code' => $status->code]);
                throw new \Exception("圖片處理失敗: " . $status->details);
            }
        } catch (\Exception $e) {
            Log::error("Error calling gRPC Image Service: " . $e->getMessage());
            throw new \Exception("呼叫圖片處理服務時發生錯誤: " . $e->getMessage());
        }
    }
}
EOF

# backend/app/Http/Controllers/Api/Admin/AuthController.php 內容 (引用 User Model)
cat << 'EOF' > backend/app/Http/Controllers/Api/Admin/AuthController.php
<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Http\Request;
use App\Models\User; // 引入 User Model

/**
 * @OA\Info(
 * version="1.0.0",
 * title="Laravel Vue Admin API Documentation",
 * description="API documentation for the Laravel Vue Admin system",
 * @OA\Contact(
 * email="support@example.com"
 * )
 * )
 * @OA\SecurityScheme(
 * securityScheme="bearerAuth",
 * type="http",
 * scheme="bearer",
 * bearerFormat="JWT"
 * )
 */
class AuthController extends Controller
{
    public function __construct()
    {
        // 登入和刷新路由不應用 JWT 中間件
        $this->middleware('auth:admin', ['except' => ['login', 'refresh']]);
    }

    /**
     * @OA\Post(
     * path="/api/admin/login",
     * operationId="adminLogin",
     * tags={"Admin Authentication"},
     * summary="Admin login",
     * description="Authenticates an admin user and returns a JWT token.",
     * @OA\RequestBody(
     * required=true,
     * @OA\JsonContent(
     * @OA\Property(property="email", type="string", format="email", example="admin@example.com"),
     * @OA\Property(property="password", type="string", format="password", example="password")
     * )
     * ),
     * @OA\Response(
     * response=200,
     * description="Login successful",
     * @OA\JsonContent(
     * @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
     * )
     * )
     * )
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (! $token = Auth::guard('admin')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return response()->json(['token' => $token], 200);
    }

    /**
     * @OA\Post(
     * path="/api/admin/logout",
     * operationId="adminLogout",
     * tags={"Admin Authentication"},
     * summary="Admin logout",
     * description="Logs out the authenticated admin user by invalidating their JWT token.",
     * security={{"bearerAuth": {}}},
     * @OA\Response(response=200, description="Successfully logged out"),
     * @OA\Response(response=401, description="Unauthorized")
     * )
     */
    public function logout()
    {
        Auth::guard('admin')->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * @OA\Post(
     * path="/api/admin/refresh",
     * operationId="adminRefreshToken",
     * tags={"Admin Authentication"},
     * summary="Refresh admin JWT token",
     * description="Refresh an expired or about-to-expire JWT token to get a new one. The old token will be blacklisted.",
     * security={{"bearerAuth": {}}},
     * @OA\Response(
     * response=200,
     * description="Token refreshed successfully",
     * @OA\JsonContent(
     * @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
     * )
     * ),
     * @OA\Response(response=401, description="Unauthorized (Token invalid, expired beyond refresh TTL, or blacklisted)")
     * )
     */
    public function refresh()
    {
        try {
            $token = Auth::guard('admin')->refresh();
            return response()->json(['token' => $token], 200);
        } catch (\Tymon\JWTAuth\Exceptions\TokenBlacklistedException $e) {
            return response()->json(['error' => 'Token has been blacklisted, please re-login.'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired beyond refresh period, please re-login.'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Could not refresh token: ' . $e->getMessage()], 401);
        }
    }

    /**
     * @OA\Get(
     * path="/api/admin/user",
     * operationId="getAdminUser",
     * tags={"Admin Authentication"},
     * summary="Get authenticated admin user",
     * description="Retrieves the details of the currently authenticated admin user.",
     * security={{"bearerAuth": {}}},
     * @OA\Response(
     * response=200,
     * description="User details retrieved successfully",
     * @OA\JsonContent(
     * @OA\Property(property="id", type="integer", example=1),
     * @OA\Property(property="name", type="string", example="Admin User"),
     * @OA\Property(property="email", type="string", format="email", example="admin@example.com")
     * )
     * ),
     * @OA\Response(response=401, description="Unauthorized")
     * )
     */
    public function user()
    {
        return response()->json(Auth::guard('admin')->user());
    }
}
EOF

# backend/app/Http/Controllers/Api/Client/AuthController.php 內容 (引用 User Model)
cat << 'EOF' > backend/app/Http/Controllers/Api/Client/AuthController.php
<?php

namespace App\Http\Controllers\Api\Client;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User; // 引入 User Model

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:client', ['except' => ['login', 'refresh']]);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (! $token = Auth::guard('client')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return response()->json(['token' => $token]);
    }

    public function logout()
    {
        Auth::guard('client')->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh()
    {
        try {
            $token = Auth::guard('client')->refresh();
            return response()->json(['token' => $token]);
        } catch (\Tymon\JWTAuth\Exceptions\TokenBlacklistedException $e) {
            return response()->json(['error' => 'Token has been blacklisted, please re-login.'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired beyond refresh period, please re-login.'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Could not refresh token: ' . $e->getMessage()], 401);
        }
    }

    public function user()
    {
        return response()->json(Auth::guard('client')->user());
    }
}
EOF

# backend/app/Http/Controllers/Api/Admin/ImageController.php 內容 (不變)
cat << 'EOF' > backend/app/Http/Controllers/Api/Admin/ImageController.php
<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Services\ImageService;
use Illuminate\Support\Facades\Log;

class ImageController extends Controller
{
    protected $imageService;

    public function __construct(ImageService $imageService)
    {
        $this->imageService = $imageService;
    }

    /**
     * @OA\Post(
     * path="/api/admin/images/upload",
     * operationId="adminUploadImage",
     * tags={"Admin Image Management"},
     * summary="Upload an image for admin",
     * description="Uploads an image and processes it via gRPC image worker.",
     * security={{"bearerAuth": {}}},
     * @OA\RequestBody(
     * required=true,
     * @OA\MediaType(
     * mediaType="multipart/form-data",
     * @OA\Schema(
     * @OA\Property(
     * property="image",
     * type="string",
     * format="binary",
     * description="Image file to upload (JPEG, PNG, JPG, max 2MB)"
     * )
     * )
     * )
     * ),
     * @OA\Response(
     * response=200,
     * description="Image processed and URL returned",
     * @OA\JsonContent(
     * @OA\Property(property="image_url", type="string", example="http://localhost/storage/images/your-image.webp")
     * )
     * ),
     * @OA\Response(response=422, description="Validation error"),
     * @OA\Response(response=500, description="Image processing failed")
     * )
     */
    public function upload(Request $request)
    {
        try {
            $imageUrl = $this->imageService->processImageViaGrpc($request);
            return response()->json(['image_url' => $imageUrl], 200);
        } catch (\Exception $e) {
            Log::error("Image upload failed: " . $e->getMessage());
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }
}
EOF

# backend/app/Models/User.php 內容
cat << 'EOF' > backend/app/Models/User.php
<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
EOF

# backend/database/migrations/${TIMESTAMP}_create_users_table.php 內容
# 注意: 這裡使用 'EOF' 而非 EOF 來避免 Shell 解析內部 PHP 變數和語法
cat << 'EOF' > backend/database/migrations/${TIMESTAMP}_create_users_table.php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Hash; // 引入 Hash facade
use App\Models\User; // 引入 User Model

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });

        // 插入一個預設的管理員用戶
        User::create([
            'name' => 'Admin User',
            'email' => 'admin@example.com',
            'password' => Hash::make('password'), // 預設密碼為 'password'
            'email_verified_at' => now(),
        ]);

        // 插入一個預設的客戶端用戶
        User::create([
            'name' => 'Client User',
            'email' => 'client@example.com',
            'password' => Hash::make('password'), // 預設密碼為 'password'
            'email_verified_at' => now(),
        ]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
EOF

# frontend-admin/package.json 內容 (不變)
cat << 'EOF' > frontend-admin/package.json
{
  "name": "frontend-admin",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.6.8",
    "pinia": "^2.1.7",
    "vue": "^3.4.21",
    "vue-router": "^4.3.0"
  },
  "devDependencies": {
    "@vitejs/plugin-vue": "^5.0.4",
    "vite": "^5.2.0"
  }
}
EOF

# frontend-admin/src/stores/auth.js 內容 (不變)
cat << 'EOF' > frontend-admin/src/stores/auth.js
// frontend-admin/src/stores/auth.js
import { defineStore } from 'pinia';
import { ref } from 'vue';
import axios from 'axios';

export const useAuthStore = defineStore('auth', () => {
    const token = ref(localStorage.getItem('admin_token') || '');
    const user = ref(JSON.parse(localStorage.getItem('admin_user') || 'null'));
    const isRefreshing = ref(false); 
    let failedRequestsQueue = []; 

    const axiosInstance = axios.create({
        baseURL: '/', 
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    });

    axiosInstance.interceptors.request.use(
        config => {
            if (token.value && !config.headers.Authorization) {
                config.headers.Authorization = `Bearer ${token.value}`;
            }
            return config;
        },
        error => Promise.reject(error)
    );

    axiosInstance.interceptors.response.use(
        response => response,
        async error => {
            const originalRequest = error.config;

            if (error.response?.status === 401 && originalRequest.url.indexOf('/refresh') === -1 && !originalRequest._retry) {
                originalRequest._retry = true; 

                if (!isRefreshing.value) {
                    isRefreshing.value = true; 
                    try {
                        const refreshResponse = await axiosInstance.post('/api/admin/refresh'); 
                        token.value = refreshResponse.data.token;
                        localStorage.setItem('admin_token', token.value);

                        failedRequestsQueue.forEach(promise => promise.resolve());
                        failedRequestsQueue = []; 
                        isRefreshing.value = false; 

                        originalRequest.headers['Authorization'] = `Bearer ${token.value}`;
                        return axiosInstance(originalRequest); 
                    } catch (refreshError) {
                        console.error('Token refresh failed:', refreshError.response?.data?.error || refreshError.message);
                        isRefreshing.value = false; 
                        failedRequestsQueue.forEach(promise => promise.reject(refreshError));
                        failedRequestsQueue = [];
                        logout(); // 刷新失敗，登出用戶
                        return Promise.reject(refreshError); 
                    }
                } else {
                    return new Promise((resolve, reject) => {
                        failedRequestsQueue.push({ resolve, reject });
                    })
                    .then(() => {
                        originalRequest.headers['Authorization'] = `Bearer ${token.value}`;
                        return axiosInstance(originalRequest);
                    })
                    .catch(refreshError => {
                        return Promise.reject(refreshError);
                    });
                }
            }
            return Promise.reject(error);
        }
    );

    async function login(credentials) {
        // 實際的登入邏輯，需要替換
        try {
            const response = await axiosInstance.post('/api/admin/login', credentials);
            token.value = response.data.token;
            localStorage.setItem('admin_token', token.value);
            // 假設登入成功後，您可以獲取用戶資訊
            // const userResponse = await axiosInstance.get('/api/admin/user');
            // user.value = userResponse.data;
            // localStorage.setItem('admin_user', JSON.stringify(user.value));
            console.log('Login successful');
            return true;
        } catch (error) {
            console.error('Login failed:', error.response?.data?.error || error.message);
            logout(); // 登入失敗則清除 token
            return false;
        }
    }

    async function fetchUser() {
        // 實際獲取用戶資訊的邏輯，需要替換
        if (!token.value) return null;
        try {
            // const response = await axiosInstance.get('/api/admin/user');
            // user.value = response.data;
            // localStorage.setItem('admin_user', JSON.stringify(user.value));
            // return user.value;
            return { name: "Test User", email: "test@example.com" }; // 佔位數據
        } catch (error) {
            console.error('Fetch user failed:', error.response?.data?.error || error.message);
            logout();
            return null;
        }
    }

    function logout() {
        // 實際的登出邏輯，可能需要發送請求到後端
        axiosInstance.post('/api/admin/logout').catch(e => console.error('Logout API failed:', e));
        token.value = '';
        user.value = null;
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_user');
        console.log('Logged out');
        // 可選：重定向到登入頁面
        // router.push('/login');
    }

    return { token, user, login, fetchUser, logout, axiosInstance }; 
});
EOF

# docker/nginx/default.conf 內容 (不變)
cat << 'EOF' > docker/nginx/default.conf
server {
    listen 80;
    server_name localhost;

    root /var/www/html/frontend-admin/dist; 
    index index.html index.htm;
    charset utf-8;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        fastcgi_pass 127.0.0.1:9000; 
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/html/backend/public/index.php;
        include fastcgi_params;
        fastcgi_param REQUEST_URI $request_uri;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }

    location /storage/ {
        alias /var/www/html/backend/storage/app/public/;
        try_files $uri $uri/ =404;
        add_header Cache-Control "public, max-age=31536000, immutable";
        add_header Access-Control-Allow-Origin "*";
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF

# docker/php/Dockerfile 內容 (backend PHP-FPM 容器，新增 gRPC Client 相關依賴)
cat << 'EOF' > docker/php/Dockerfile
# docker/php/Dockerfile
FROM php:8.3-fpm-alpine

# 安裝系統依賴和 PHP 擴展
RUN apk add --no-cache \
    nginx \ 
    libzip-dev \
    libpng-dev \
    jpeg-dev \
    libwebp-dev \
    freetype-dev \
    libjpeg-turbo-dev \
    webp-dev \
    mysql-client \
    git \
    unzip \
    grpc-dev \
    protobuf-dev \
    build-base # 編譯所需，用於 gd 擴展

# 安裝 PHP 擴展 (新增 grpc, protobuf)
RUN pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j$(nproc) gd pdo_mysql zip opcache redis

# 清理編譯工具
RUN apk del build-base

# 安裝 Composer
COPY --from=composer/composer:latest-bin /composer /usr/bin/composer

# 設定工作目錄為 /var/www/html
WORKDIR /var/www/html

# 複製 backend 程式碼
COPY backend ./backend

# 暴露端口
EXPOSE 9000 # PHP-FPM
EXPOSE 80   # Nginx

# CMD 將被 docker-compose.yml 中的 `command` 覆蓋
EOF

# docker/frontend/Dockerfile 內容 (不變)
cat << 'EOF' > docker/frontend/Dockerfile
# docker/frontend/Dockerfile
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend-admin

COPY frontend-admin/package*.json ./

RUN npm install

COPY frontend-admin ./

CMD ["npm", "run", "build"]
EOF

# grpc-service/proto/image.proto 內容 (不變)
cat << 'EOF' > grpc-service/proto/image.proto
syntax = "proto3";

package ImageProcessor; // 定義包名

// 服務定義
service ImageProcessor {
  // 定義一個處理圖片的 RPC 方法
  rpc ProcessImage (ImageRequest) returns (ImageResponse);
}

// 請求消息
message ImageRequest {
  bytes image_data = 1; // 圖片的二進制數據
  string filename = 2; // 原始文件名
}

// 響應消息
message ImageResponse {
  string image_url = 1; // 處理後圖片的 URL
}
EOF

# grpc-service/src/Services/ImageProcessorImplementation.php 內容 (不變)
cat << 'EOF' > grpc-service/src/Services/ImageProcessorImplementation.php
<?php

namespace Grpc\ImageProcessor\Services;

use Grpc\ImageProcessor\ImageRequest;
use Grpc\ImageProcessor\ImageResponse;
use Grpc\ImageProcessor\ImageProcessorGrpcInterface; // 由 protoc 生成的介面
use Spiral\RoadRunner\GRPC\ContextInterface;
use Intervention\Image\Facades\Image; // 引入 Intervention/Image
use Illuminate\Support\Facades\Storage; // 引入 Storage facade
use Illuminate\Support\Str; // 引入 Str 輔助函數
use Illuminate\Support\Facades\Log; // 引入 Log

// 這邊需要安裝 Intervention/Image 和 Laravel 的 Storage facade
// 在 RoadRunner 環境下，可能需要手動載入 Laravel 的部分組件，
// 或者考慮讓這個服務依賴 Laravel 的核心檔案。
// 為了簡化，這裡假設這些依賴已在容器內可用。
// 實際生產環境中，此處應為一個更獨立的服務，其文件系統操作應直接調用底層庫。
// 為了演示，我們直接使用 Storage facade 並假設它可以訪問到 Laravel 的 storage 路徑。

class ImageProcessorImplementation implements ImageProcessorGrpcInterface
{
    /**
     * 處理圖片並返回 URL。
     *
     * @param ContextInterface $context
     * @param ImageRequest $request
     * @return ImageResponse
     */
    public function ProcessImage(ContextInterface $context, ImageRequest $request): ImageResponse
    {
        try {
            $imageData = $request->getImageData();
            $originalFilename = $request->getFilename();

            // 生成唯一文件名，確保不重複
            $filenameWithoutExt = pathinfo($originalFilename, PATHINFO_FILENAME);
            $newFilename = Str::slug($filenameWithoutExt) . '-' . time() . '-' . Str::random(8) . '.webp';

            // 使用 Intervention/Image 處理圖片
            $image = Image::make($imageData);

            // 調整圖片大小，限制寬度為 1200px，高度按比例
            $image->resize(1200, null, function ($constraint) {
                $constraint->aspectRatio();
                $constraint->upsize(); // 只有圖片大於 1200px 時才縮小
            });

            // 轉換為 WebP 格式，質量 80
            $webpContent = $image->encode('webp', 80);

            // 儲存到 Laravel 的 public 儲存碟 (對應到 storage/app/public)
            // 注意: 在獨立的 gRPC 服務中，需要確保此路徑是可寫的，並且與 Nginx 服務的路徑一致。
            // 這通常意味著需要共享卷或將文件上傳到雲儲存。
            // 為了簡化 Docker Compose 範例，我們假設它能寫入到共享給 Nginx 的目錄。
            $storagePath = 'images/' . $newFilename;
            Storage::disk('public')->put($storagePath, $webpContent);

            $imageUrl = '/storage/' . $storagePath; // 返回相對 URL，由 Nginx 服務

            Log::info("Image processed by gRPC worker: " . $newFilename);

            $response = new ImageResponse();
            $response->setImageUrl($imageUrl);

            return $response;

        } catch (\Exception $e) {
            Log::error("gRPC Image processing error: " . $e->getMessage(), [
                'filename' => $originalFilename,
                'trace' => $e->getTraceAsString()
            ]);
            // 根據 gRPC 錯誤處理，可以拋出異常或返回帶有錯誤信息的響應
            // 這裡拋出異常，讓 RoadRunner 處理為 gRPC 錯誤狀態
            throw new \Exception("Failed to process image: " . $e->getMessage());
        }
    }
}
EOF

# grpc-service/composer.json 內容 (不變)
cat << 'EOF' > grpc-service/composer.json
{
    "name": "your-org/image-grpc-worker",
    "description": "A gRPC service for image processing.",
    "type": "project",
    "require": {
        "php": ">=8.1",
        "spiral/roadrunner": "^2.10 || ^3.0",
        "spiral/roadrunner-grpc": "^2.10 || ^3.0",
        "google/protobuf": "^3.23",
        "grpc/grpc": "^1.40",
        "intervention/image": "^2.7",
        "illuminate/support": "^10.0 || ^11.0",
        "illuminate/filesystem": "^10.0 || ^11.0"
    },
    "autoload": {
        "psr-4": {
            "Grpc\\ImageProcessor\\": "src/Grpc/ImageProcessor/",
            "Grpc\\ImageProcessor\\Services\\": "src/Services/"
        },
        "files": [
            "src/support_laravel_facades.php" # 引入 Laravel Facade 支援
        ]
    },
    "scripts": {
        "proto:generate": "protoc --proto_path=./proto --php_out=src/Grpc/ImageProcessor --grpc_out=src/Grpc/ImageProcessor --plugin=protoc-gen-grpc=$(which grpc_php_plugin) proto/image.proto"
    },
    "config": {
        "allow-plugins": {
            "php-http/discovery": true
        }
    }
}
EOF

# grpc-service/server.php 內容 (不變)
cat << 'EOF' > grpc-service/server.php
<?php

// grpc-service/server.php
require __DIR__ . '/vendor/autoload.php';

use Spiral\RoadRunner\Worker;
use Spiral\RoadRunner\GRPC\GRPC;
use Grpc\ImageProcessor\Services\ImageProcessorImplementation;
use Grpc\ImageProcessor\ImageProcessorGrpcInterface;

// 創建 Worker
$worker = Worker::create();

// 創建 gRPC 服務器
$grpc = new GRPC();

// 註冊您的 gRPC 服務
$grpc->addService(
    new \ReflectionClass(ImageProcessorGrpcInterface::class),
    new ImageProcessorImplementation()
);

// 啟動 gRPC 服務器
$grpc->serve($worker);

// 注意：RoadRunner 會接管輸出，此行不會直接顯示
// echo "gRPC Image Worker server started...\n";
EOF

# grpc-service/.rr.yaml 內容 (不變)
cat << 'EOF' > grpc-service/.rr.yaml
# .rr.yaml for gRPC Image Worker
version: "2.7" # 或更高版本

grpc:
  listen: "tcp://0.0.0.0:50051" # gRPC 服務監聽的端口
  proto:
    - "proto/image.proto" # 您的 Protobuf 文件路徑
  services:
    - "ImageProcessor.ImageProcessor" # 您的 Protobuf 服務名稱 (packageName.serviceName)

http:
  address: "0.0.0.0:8080" # 如果需要 HTTP 介面，但 gRPC 服務通常不需要

rpc:
  listen: "tcp://127.0.0.1:6001" # RoadRunner 的內部 RPC 端口 (用於監控等)

jobs:
  pipelines: {} # 如果 gRPC 服務內部也需要 RoadRunner 任務佇列

# 工作進程配置
server:
  command: "php server.php" # 執行 PHP gRPC 服務的命令
  pool:
    num_workers: 2 # 根據需求調整工作進程數量
    max_jobs: 0 # 0 表示無限
    supervise:
      max_seq_exec: 1000 # 避免記憶體洩漏，達到次數後重啟
      ttl: 60s
      idle_ttl: 10s
EOF

# grpc-service/src/support_laravel_facades.php 內容 (用於在 gRPC 服務中支援 Laravel Facades)
cat << 'EOF' > grpc-service/src/support_laravel_facades.php
<?php
// grpc-service/src/support_laravel_facades.php
// 這是為了讓 Intervention/Image 和 Storage Facade 在獨立的 RoadRunner 環境中工作的簡易配置。
// 在生產環境中，推薦更完善的 Laravel Console Kernel 或獨立的應用程序引導。

use Illuminate\Container\Container;
use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Log; // Add Log Facade

// 建立一個 IoC 容器實例
$app = Container::getInstance();
if (!$app) {
    $app = new Container();
    Container::setInstance($app);
}

// 綁定 Log Facade
if (!$app->bound('log')) {
    $app->singleton('log', function () {
        // 配置 Monolog 記錄器
        $logger = new \Monolog\Logger('grpc-worker');
        $handler = new \Monolog\Handler\StreamHandler('php://stderr', \Monolog\Logger::DEBUG);
        $logger->pushHandler($handler);
        return $logger;
    });
    Log::setFacadeApplication($app);
}

// 綁定 'files' 服務 (Illuminate\Filesystem\Filesystem)
if (!$app->bound('files')) {
    $app->singleton('files', function () {
        return new \Illuminate\Filesystem\Filesystem();
    });
}

// 綁定 'config' 服務 (用於 Storage Manager 讀取配置)
if (!$app->bound('config')) {
    $app->singleton('config', function () {
        return new \Illuminate\Config\Repository([
            'filesystems' => [
                'default' => 'public',
                'disks' => [
                    'public' => [
                        'driver' => 'local',
                        // 將 path 指向 Laravel backend 的 storage/app/public 目錄
                        // 這需要透過 Docker volume 掛載來實現共享
                        'root' => '/var/www/html/backend/storage/app/public', 
                        'url' => env('APP_URL') . '/storage',
                        'visibility' => 'public',
                    ],
                    // 其他 disk 配置...
                ],
            ],
            // 這裡可以添加其他必要的配置，例如 app.url
            'app' => [
                'url' => 'http://localhost', // 根據您的環境調整
            ]
        ]);
    });
}


// 綁定 'filesystem' 服務 (Illuminate\Filesystem\FilesystemManager)
if (!$app->bound('filesystem')) {
    $app->singleton('filesystem', function ($app) {
        return new FilesystemManager($app);
    });
}


// 設定 Facade 的應用實例
Facade::setFacadeApplication($app);

// 註冊 Intervention/Image Facade
// 在 RoadRunner 環境中，可能需要手動引入 ImageManager
// 確保已安裝 intervention/image
if (class_exists('Intervention\Image\ImageManager')) {
    // 創建一個 ImageManager 實例
    $manager = new \Intervention\Image\ImageManager(array('driver' => 'gd'));
    
    // 將 ImageManager 實例綁定到容器
    if (!$app->bound('image')) {
        $app->singleton('image', function() use ($manager) {
            return $manager;
        });
    }

    // 將 Intervention\Image\Facades\Image 指向綁定的實例
    // 這一步可能在 composer autoload 中處理，但手動確保
}

// 確保 Storage Facade 正常工作
\Illuminate\Support\Facades\Storage::swap(\Illuminate\Support\Facades\App::make('filesystem'));

// 其他需要手動綁定的 Facades...

// 設置時區，避免日期時間警告
date_default_timezone_set(env('APP_TIMEZONE', 'UTC'));

// 由於 RoadRunner 是一個長期運行的進程，需要小心記憶體洩漏
// 和請求之間的狀態污染。這裡的 Facade 綁定是簡化的示例。
EOF

# docker/grpc/Dockerfile 內容 (gRPC Image Worker 容器)
cat << 'EOF' > docker/grpc/Dockerfile
# docker/grpc/Dockerfile
FROM php:8.3-cli-alpine AS grpc-builder

WORKDIR /app/grpc-service

# 安裝系統依賴和 PHP 擴展
RUN apk add --no-cache \
    git \
    unzip \
    libzip-dev \
    libpng-dev \
    jpeg-dev \
    libwebp-dev \
    freetype-dev \
    libjpeg-turbo-dev \
    webp-dev \
    grpc-dev \
    protobuf-dev \
    build-base # 編譯所需，用於 gd 擴展

# 安裝 PHP gRPC 和 Protobuf 擴展
RUN pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j$(nproc) gd

# 清理編譯工具
RUN apk del build-base

# 安裝 Composer
COPY --from=composer/composer:latest-bin /composer /usr/bin/composer

# 複製 gRPC 服務的 composer.json 和 lock 文件
COPY grpc-service/composer.json grpc-service/composer.lock ./

# 安裝 Composer 依賴
RUN composer install --no-dev --optimize-autoloader

# 複製所有 gRPC 服務程式碼和 proto 文件
COPY grpc-service .

# 從 RoadRunner releases 下載 rr 二進制文件
ARG RR_VERSION=2.12.0 # 或您希望使用的最新穩定版本
RUN wget https://github.com/roadrunner-server/roadrunner/releases/download/v${RR_VERSION}/rr-v${RR_VERSION}-linux-amd64.tar.gz -O /tmp/rr.tar.gz \
    && tar -xzf /tmp/rr.tar.gz -C /usr/local/bin rr \
    && rm /tmp/rr.tar.gz \
    && chmod +x /usr/local/bin/rr

# 生成 PHP gRPC stubs
# 注意: grpc_php_plugin 需要在 PATH 中
RUN composer run proto:generate

FROM php:8.3-cli-alpine

WORKDIR /app/grpc-service

COPY --from=grpc-builder /app/grpc-service/vendor ./vendor
COPY --from=grpc-builder /app/grpc-service/src ./src
COPY --from=grpc-builder /app/grpc-service/proto ./proto
COPY --from=grpc-builder /app/grpc-service/server.php ./server.php
COPY --from=grpc-builder /app/grpc-service/.rr.yaml ./.rr.yaml
COPY --from=grpc-builder /usr/local/bin/rr /usr/local/bin/rr

# 安裝運行時所需的 PHP 擴展
RUN apk add --no-cache \
    grpc-dev \
    protobuf-dev && \
    pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-install gd

# 暴露 gRPC 端口
EXPOSE 50051

# 啟動 gRPC RoadRunner server
CMD ["rr", "serve", "-c", ".rr.yaml", "--debug"]
EOF

# docker-compose.yml 內容 (新增 mysql 服務，更新 backend 依賴和命令)
cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  # 前端構建服務
  frontend:
    build:
      context: .
      dockerfile: docker/frontend/Dockerfile
    container_name: vue-laravel-archi-frontend-builder
    volumes:
      - ./frontend-admin:/app/frontend-admin 
      - frontend_dist:/app/frontend-admin/dist 
    command: ["npm", "run", "build"]
    restart: "no"

  # 後端應用服務 (包含 PHP-FPM 和 Nginx)
  backend:
    build:
      context: .
      dockerfile: docker/php/Dockerfile
    container_name: vue-laravel-archi-backend
    volumes:
      - ./backend:/var/www/html/backend # Laravel 後端程式碼
      - frontend_dist:/var/www/html/frontend-admin/dist 
      - ./docker/nginx/default.conf:/etc/nginx/conf.d/default.conf 
      - backend_storage_public:/var/www/html/backend/storage/app/public # 持久化圖片儲存 (共享卷)

    ports:
      - "80:80"   # 只映射 HTTP 端口

    env_file:
      - ./backend/.env

    environment:
      - APP_ENV=production
      - APP_DEBUG=false
      - DB_HOST=mysql # 指向 MySQL 服務
      - REDIS_HOST=redis
      - REDIS_PASSWORD=${REDIS_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
      - IMAGE_GRPC_HOST=image-worker # 指向 gRPC 服務的內部 Docker 網路名稱
      - IMAGE_GRPC_PORT=50051

    depends_on:
      - frontend 
      - redis    
      - mysql      # 新增依賴 MySQL 服務
      - image-worker # 新增依賴 gRPC 圖片處理服務

    command: >
      sh -c "
      cd /var/www/html/backend && 
      composer install --no-dev --optimize-autoloader && 
      php artisan optimize && 
      php artisan migrate --force && # 執行資料庫遷移
      php artisan storage:link && 
      php-fpm -D && # 後台運行 PHP-FPM
      # php artisan queue:work --daemon & # 如果沒有其他佇列任務，可以移除此行
      nginx -g 'daemon off;' # 前台運行 Nginx，保持容器活動
      "
    restart: always

  # MySQL 資料庫服務
  mysql:
    image: mysql:8.0
    container_name: vue-laravel-archi-mysql
    ports:
      - "3306:3306" # 可選：暴露 MySQL 端口到宿主機
    environment:
      MYSQL_ROOT_PASSWORD: root_password # 替換為您的 root 密碼
      MYSQL_DATABASE: laravel_vue_db
      MYSQL_USER: laravel_user
      MYSQL_PASSWORD: laravel_password
    volumes:
      - mysql_data:/var/lib/mysql # 持久化 MySQL 資料
    command: --default-authentication-plugin=mysql_native_password
    restart: always

  # Redis 服務
  redis:
    image: redis:7-alpine 
    container_name: vue-laravel-archi-redis
    ports:
      - "6379:6379" # 可選：暴露 Redis 端口到宿主機
    volumes:
      - redis_data:/data # 持久化 Redis 資料
    command: redis-server --appendonly yes
    restart: always

  # gRPC Image Worker 服務
  image-worker:
    build:
      context: .
      dockerfile: docker/grpc/Dockerfile # 使用 gRPC 服務的 Dockerfile
    container_name: vue-laravel-archi-image-worker
    volumes:
      - ./grpc-service:/app/grpc-service # 掛載 gRPC 服務程式碼
      # 共享圖片儲存卷，讓 gRPC worker 可以寫入，Nginx 可以讀取
      - backend_storage_public:/var/www/html/backend/storage/app/public 
    ports:
      - "50051:50051" # 暴露 gRPC 服務端口
    env_file:
      - ./backend/.env # 使用 backend 的 .env 來獲取 APP_URL 等配置
    environment:
      - APP_ENV=production
      - APP_DEBUG=false
      - APP_URL=http://localhost # 確保在 gRPC worker 中也能正確構建 URL
      # RoadRunner 的 gRPC 監聽端口配置
      - RR_GRPC_LISTEN=tcp://0.0.0.0:50051
      # 如果 image-worker 內部也需要 Redis，則需要指向
      - REDIS_HOST=redis 
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    depends_on:
      - redis # 假設 gRPC worker 內部可能也需要 Redis
    command: ["rr", "serve", "-c", ".rr.yaml", "--debug"] # 啟動 RoadRunner gRPC server
    restart: always

# 定義具名卷
volumes:
  frontend_dist:
  redis_data:
  mysql_data: # 新增 MySQL 資料卷
  backend_storage_public: # 新增用於共享 Laravel public 儲存的卷
EOF

# .gitignore 內容 (不變)
cat << 'EOF' > .gitignore
# 環境變數
.env
.env.production
.env.testing

# Laravel 相關
/backend/vendor/
/backend/node_modules/
/backend/storage/*.key
/backend/public/storage
/backend/public/hot
/backend/.phpunit.result.cache
/backend/build-*
/backend/app/GrpcStubs/ # 由 protoc 生成的 Laravel gRPC stubs

# Vue 相關
/frontend-admin/node_modules/
/frontend-admin/dist/
/frontend-admin/coverage/
/frontend-admin/.vite/

# Docker 相關
/.dockerignore

# gRPC 服務相關
/grpc-service/vendor/
/grpc-service/src/Grpc/ # 由 protoc 生成的 gRPC 服務 stubs
/grpc-service/rr # RoadRunner 二進制文件 (如果直接放在專案內)

# 系統文件
.DS_Store
Thumbs.db
EOF

echo "專案架構已成功建立在 ./$PROJECT_ROOT 目錄中，並整合了 gRPC Image Worker！"
echo "請進入該目錄：cd $PROJECT_ROOT"
echo "接下來，您需要手動完成以下步驟：\n"
echo "1. **重要**：在您的本機系統或 Docker 構建環境中安裝 \`protoc\` (Protocol Buffers 編譯器) 和 \`grpc_php_plugin\`。這些工具用於從 \`.proto\` 文件生成 PHP 程式碼。\n   例如 (Ubuntu):"
echo "   sudo apt-get install protobuf-compiler"
echo "   # 下載並安裝 grpc_php_plugin，參考 gRPC PHP 官方文件獲取最新版本和安裝方式"
echo "   # 例如: wget https://github.com/grpc/grpc/releases/download/vX.Y.Z/grpc_php_plugin_linux_x64 --output-document=/usr/local/bin/grpc_php_plugin && chmod +x /usr/local/bin/grpc_php_plugin"
echo "   **確保 \`grpc_php_plugin\` 在您的 PATH 中**\n"
echo "2. 在 'backend/.env' 中設置 'APP_KEY' 和 'JWT_SECRET'。您可以啟動 backend 容器後執行 'php artisan key:generate' 和 'php artisan jwt:secret' 來生成。\n"
echo "3. 運行 'docker compose up --build -d' 來構建並啟動所有服務。\n"
echo "4. 由於 \`backend/database/migrations/${TIMESTAMP}_create_users_table.php\` 中包含了預設用戶的建立，一旦容器啟動並執行 \`php artisan migrate --force\`，資料庫中將會自動創建 \`users\` 表並插入 'admin@example.com' 和 'client@example.com' 兩個預設用戶（密碼皆為 'password'）。"
echo "應用程式將在 http://localhost/ 運行。\n"
echo "圖片上傳現在將透過 Laravel API 呼叫內部的 gRPC Image Worker 服務處理。"