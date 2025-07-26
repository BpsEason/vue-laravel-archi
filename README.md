# Vue-Laravel-Archi 專案

這是一個基於 Laravel 11 和 Vue3 的全棧應用，整合 Docker Compose 和 gRPC，專為內網或本地開發環境設計。後端提供 RESTful API，前端用 Vue3 + Pinia 打造管理介面，圖片處理透過獨立的 gRPC 服務轉為 WebP 格式並儲存到本地。專案不含 HTTPS 配置，適合快速原型開發或內部工具使用。

## 專案架構

- **後端**: Laravel 11，支援 JWT 認證、Swagger 文件、Redis 快取與 Session 管理。
- **前端**: Vue3 + Pinia + Vue Router，編譯後的靜態檔案由 Nginx 提供。
- **資料庫**: MySQL 8.0，包含預設 `users` 表和測試用戶。
- **快取**: Redis 7 (Alpine)，啟用 AOF 持久化。
- **圖片處理**: 獨立 gRPC 服務 (RoadRunner)，使用 Intervention/Image 處理圖片。
- **容器化**: Docker Compose 管理 `frontend`（構建 Vue）、`backend`（Laravel + Nginx）、`mysql`、`redis` 和 `image-worker`（gRPC）服務。
- **Nginx**: 跑在 `backend` 容器內，負責靜態檔案和 API 反向代理，圖片設長效快取。

## 目錄結構

```
vue-laravel-archi/
├── backend/                              # Laravel 後端
│   ├── app/                             # 應用程式核心
│   │   ├── Http/Controllers/Api/        # API 控制器
│   │   │   ├── Admin/                   # 管理員端點
│   │   │   │   ├── AuthController.php   # 認證相關 API
│   │   │   │   └── ImageController.php  # 圖片上傳 API
│   │   │   └── Client/                  # 客戶端端點
│   │   │       └── AuthController.php   # 客戶端認證 API
│   │   ├── Models/                      # Eloquent 模型
│   │   │   └── User.php                 # 用戶模型
│   │   ├── Services/                    # 業務邏輯服務
│   │   │   └── ImageService.php         # 圖片處理服務
│   │   └── GrpcStubs/                   # gRPC 客戶端 stubs（由 protoc 生成）
│   │       └── ImageWorkerClient.php    # gRPC 客戶端
│   ├── config/                          # Laravel 配置
│   ├── database/                        # 資料庫相關
│   │   ├── migrations/                  # 資料庫遷移
│   │   │   └── <TIMESTAMP>_create_users_table.php  # 用戶表遷移
│   │   ├── factories/                   # 資料工廠
│   │   └── seeders/                     # 資料種子
│   ├── routes/                          # API 路由
│   │   └── api.php                      # API 路由定義
│   ├── storage/                         # 儲存空間
│   │   ├── app/public/                  # 圖片儲存
│   │   ├── logs/                        # 日誌
│   │   └── framework/                   # 框架快取
│   │       ├── cache/
│   │       ├── sessions/
│   │       └── views/
│   ├── tests/                           # 測試檔案
│   ├── composer.json                    # 後端依賴
│   ├── .env                             # 環境變數
│   └── public/                          # Laravel 公開目錄
├── frontend-admin/                      # Vue3 前端
│   ├── src/                            # Vue 原始碼
│   │   ├── stores/                     # Pinia 狀態管理
│   │   │   └── auth.js                 # JWT 認證邏輯
│   │   ├── main.js                     # Vue 入口
│   │   └── App.vue                     # 主組件
│   ├── public/                         # 靜態資源
│   ├── dist/                           # 編譯輸出（.gitignore）
│   ├── package.json                    # Node 依賴
│   └── vite.config.js                  # Vite 配置
├── grpc-service/                       # gRPC 圖片處理服務
│   ├── proto/                         # Protobuf 定義
│   │   └── image.proto                # 圖片處理 Protobuf
│   ├── src/                           # gRPC 實現
│   │   ├── Grpc/ImageProcessor/       # gRPC stubs（由 protoc 生成）
│   │   ├── Services/                  # 服務邏輯
│   │   │   └── ImageProcessorImplementation.php  # 圖片處理實現
│   │   └── support_laravel_facades.php # Laravel Facade 支援
│   ├── composer.json                  # gRPC 依賴
│   ├── server.php                     # RoadRunner 服務入口
│   └── .rr.yaml                      # RoadRunner 配置
├── docker/                             # Docker 配置
│   ├── nginx/                         # Nginx 配置
│   │   └── default.conf               # Nginx 反向代理配置
│   ├── php/                           # 後端 Dockerfile
│   │   └── Dockerfile
│   ├── frontend/                      # 前端 Dockerfile
│   │   └── Dockerfile
│   └── grpc/                          # gRPC Dockerfile
│       └── Dockerfile
├── docker-compose.yml                 # 服務編排
└── .gitignore                         # Git 忽略規則
```

## 環境需求

- Docker & Docker Compose（v2.0+）
- Bash 環境（Linux/MacOS，Windows 用 WSL）
- `protoc` 和 `grpc_php_plugin`（用於生成 gRPC stubs）
- 記憶體至少 4GB，硬碟 10GB 以上

## 安裝步驟

1. **Clone 專案**
   ```bash
   git clone https://github.com/BpsEason/vue-laravel-archi.git
   cd vue-laravel-archi
   ```

2. **安裝 `protoc` 和 `grpc_php_plugin`**
   - Ubuntu 示例：
     ```bash
     sudo apt-get install protobuf-compiler
     wget https://github.com/grpc/grpc/releases/download/v1.40.0/grpc_php_plugin -O /usr/local/bin/grpc_php_plugin
     chmod +x /usr/local/bin/grpc_php_plugin
     ```
   - 確保 `grpc_php_plugin` 在 PATH 中，詳見 [gRPC PHP 文件](https://grpc.io/docs/languages/php/quickstart/).

3. **生成 gRPC Stubs**
   ```bash
   cd grpc-service
   composer install
   composer run proto:generate
   ```
   這會在 `grpc-service/src/Grpc/ImageProcessor/` 生成 PHP stubs。

4. **設置環境變數**
   - 複製並編輯 `backend/.env`：
     ```env
     APP_NAME=LaravelVueApp
     APP_ENV=local
     APP_KEY= # 執行 `php artisan key:generate` 後填入
     JWT_SECRET= # 執行 `php artisan jwt:secret` 後填入
     DB_HOST=mysql
     DB_DATABASE=laravel_vue_db
     DB_USERNAME=laravel_user
     DB_PASSWORD=laravel_password
     REDIS_HOST=redis
     IMAGE_GRPC_HOST=image-worker
     IMAGE_GRPC_PORT=50051
     ```
   - 可選：調整 `docker-compose.yml` 中的 `MYSQL_ROOT_PASSWORD` 和 `REDIS_PASSWORD`。

5. **啟動容器**
   ```bash
   docker compose up --build -d
   ```
   服務端口：
   - 前端/後端: `http://localhost:80`
   - MySQL: `localhost:3306`
   - Redis: `localhost:6379`
   - gRPC: `localhost:50051`

6. **初始化資料庫**
   - `docker-compose.yml` 自動運行 `php artisan migrate --force`，創建 `users` 表並插入預設用戶：
     - 管理員: `admin@example.com` / `password`
     - 客戶端: `client@example.com` / `password`

7. **驗證服務**
   - 訪問 `http://localhost` 查看前端介面。
   - 使用 Postman 或 curl 測試 API，例如：
     ```bash
     curl -X POST http://localhost/api/admin/login -d '{"email":"admin@example.com","password":"password"}'
     ```
   - 測試圖片上傳：
     ```bash
     curl -X POST -F "image=@test.jpg" http://localhost/api/admin/images/upload -H "Authorization: Bearer <your-jwt-token>"
     ```
   - 查看 Swagger 文件：`http://localhost/api/documentation`（需自行配置 L5-Swagger）。

## 關鍵程式碼

以下是專案中的關鍵程式碼，包含詳細註解，展示核心功能實現。

### 後端：圖片上傳 API
檔案：`backend/app/Http/Controllers/Api/Admin/ImageController.php`

```php
<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Services\ImageService;
use Illuminate\Http\Request;

class ImageController extends Controller
{
    protected $imageService;

    public function __construct(ImageService $imageService)
    {
        // 注入 ImageService，用於處理圖片上傳邏輯
        $this->imageService = $imageService;
        // 限制僅管理員角色可訪問
        $this->middleware('auth:api');
        $this->middleware('role:admin');
    }

    /**
     * @OA\Post(
     *     path="/api/admin/images/upload",
     *     summary="上傳圖片並透過 gRPC 轉為 WebP",
     *     tags={"Admin Images"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 @OA\Property(
     *                     property="image",
     *                     type="file",
     *                     description="圖片檔案"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response=200, description="圖片上傳成功"),
     *     @OA\Response(response=400, description="無效的圖片檔案")
     * )
     */
    public function upload(Request $request)
    {
        // 驗證上傳的檔案是否為圖片
        $request->validate([
            'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048',
        ]);

        // 取得上傳的圖片檔案
        $image = $request->file('image');
        // 透過 ImageService 處理圖片（調用 gRPC 服務）
        $result = $this->imageService->processImage($image);

        // 檢查處理結果
        if ($result['success']) {
            return response()->json([
                'message' => '圖片上傳成功',
                'path' => $result['path'],
            ], 200);
        }

        return response()->json([
            'message' => '圖片處理失敗',
            'error' => $result['error'],
        ], 400);
    }
}
```

**說明**：
- 負責處理圖片上傳的 API，僅限管理員訪問。
- 使用 `ImageService` 與 gRPC 服務通訊，將圖片轉為 WebP 格式。
- 包含 Swagger 註解，方便生成 API 文件。

### 前端：JWT 認證邏輯
檔案：`frontend-admin/src/stores/auth.js`

```javascript
import { defineStore } from 'pinia';
import axios from 'axios';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || null, // 從 localStorage 取得 JWT
    user: JSON.parse(localStorage.getItem('user')) || null, // 儲存用戶資訊
  }),

  actions: {
    // 登入請求
    async login(credentials) {
      try {
        const response = await axios.post('/api/admin/login', credentials);
        this.token = response.data.token;
        this.user = response.data.user;
        // 儲存 token 和用戶資訊到 localStorage
        localStorage.setItem('token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        // 設置 axios 的默認 Authorization 頭
        axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
      } catch (error) {
        console.error('登入失敗:', error);
        throw error;
      }
    },

    // 登出
    logout() {
      this.token = null;
      this.user = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      delete axios.defaults.headers.common['Authorization'];
    },

    // 自動刷新 JWT token
    async refreshToken() {
      try {
        const response = await axios.post('/api/admin/refresh');
        this.token = response.data.token;
        localStorage.setItem('token', this.token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
      } catch (error) {
        console.error('Token 刷新失敗:', error);
        this.logout();
      }
    },
  },
});

// Axios 攔截器：處理 401 錯誤並自動刷新 token
axios.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      const authStore = useAuthStore();
      await authStore.refreshToken();
      // 重試原始請求
      return axios(error.config);
    }
    return Promise.reject(error);
  }
);
```

**說明**：
- 使用 Pinia 管理 JWT 認證狀態，儲存 token 和用戶資訊。
- 支援登入、登出和自動刷新 token。
- Axios 攔截器自動處理 401 錯誤並重試請求。

### gRPC 服務：圖片處理實現
檔案：`grpc-service/src/Services/ImageProcessorImplementation.php`

```php
<?php

namespace App\Grpc\Services;

use App\Grpc\ImageProcessor\ImageRequest;
use App\Grpc\ImageProcessor\ImageResponse;
use Intervention\Image\ImageManagerStatic as Image;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;

class ImageProcessorImplementation
{
    /**
     * 處理圖片並轉為 WebP 格式
     *
     * @param ImageRequest $request gRPC 請求，包含圖片數據
     * @param ImageResponse $response gRPC 回應，包含處理結果
     * @return ImageResponse
     */
    public function ProcessImage($request, $response)
    {
        try {
            // 從 gRPC 請求取得圖片數據
            $imageData = $request->getImageData();
            $filename = $request->getFilename();

            // 使用 Intervention/Image 將圖片轉為 WebP
            $image = Image::make($imageData)->encode('webp', 80);
            $webpContent = $image->getEncoded();

            // 生成新檔案名稱
            $newFilename = pathinfo($filename, PATHINFO_FILENAME) . '.webp';
            $storagePath = 'images/' . $newFilename;

            // 儲存轉換後的圖片到共享卷
            Storage::disk('public')->put($storagePath, $webpContent);
            Log::info('圖片處理成功: ' . $storagePath);

            // 設置 gRPC 回應
            $response->setSuccess(true);
            $response->setPath($storagePath);
            $response->setMessage('圖片轉換為 WebP 成功');
        } catch (\Exception $e) {
            // 處理錯誤並記錄日誌
            Log::error('圖片處理失敗: ' . $e->getMessage());
            $response->setSuccess(false);
            $response->setMessage($e->getMessage());
        }

        return $response;
    }
}
```

**說明**：
- 實現 gRPC 的圖片處理邏輯，將上傳的圖片轉為 WebP 格式。
- 使用 `Storage` Facade 儲存檔案到共享卷。
- 包含錯誤處理和日誌記錄。

### Docker 配置：服務編排
檔案：`docker-compose.yml`

```yaml
version: '3.8'

services:
  frontend:
    build:
      context: .
      dockerfile: docker/frontend/Dockerfile
    container_name: vue-laravel-archi-frontend
    volumes:
      - ./frontend-admin:/app
      - frontend_dist:/app/dist
    restart: unless-stopped

  backend:
    build:
      context: .
      dockerfile: docker/php/Dockerfile
    container_name: vue-laravel-archi-backend
    volumes:
      - ./backend:/var/www/html/backend
      - frontend_dist:/var/www/html/frontend-admin/dist
      - backend_storage_public:/var/www/html/backend/storage/app/public
    depends_on:
      - mysql
      - redis
    command: >
      sh -c "
        composer install &&
        php artisan key:generate &&
        php artisan jwt:secret &&
        php artisan migrate --force &&
        php-fpm
      "
    restart: unless-stopped

  mysql:
    image: mysql:8.0
    container_name: vue-laravel-archi-mysql
    environment:
      MYSQL_ROOT_PASSWORD: root_password
      MYSQL_DATABASE: laravel_vue_db
      MYSQL_USER: laravel_user
      MYSQL_PASSWORD: laravel_password
    volumes:
      - mysql_data:/var/lib/mysql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: vue-laravel-archi-redis
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped

  image-worker:
    build:
      context: .
      dockerfile: docker/grpc/Dockerfile
    container_name: vue-laravel-archi-image-worker
    volumes:
      - ./grpc-service:/app
      - backend_storage_public:/var/www/html/backend/storage/app/public
    ports:
      - "50051:50051"
    depends_on:
      - backend
    command: php /app/server.php
    restart: unless-stopped

volumes:
  frontend_dist:
  backend_storage_public:
  mysql_data:
  redis_data:
```

**說明**：
- 定義五個服務：前端構建 (`frontend`)、後端 (`backend`)、MySQL (`mysql`)、Redis (`redis`) 和 gRPC 圖片處理 (`image-worker`)。
- 使用共享卷 (`frontend_dist`, `backend_storage_public`) 實現前端靜態檔案和圖片檔案的共享。
- 自動執行 Laravel 的初始化命令（`composer install`, `key:generate`, `jwt:secret`, `migrate`）。

## 使用方式

- **前端**：訪問 `http://localhost`，以 `admin@example.com` 登入後台。
- **API**：
  - 管理員端點：`/api/admin/*`（如 `/api/admin/login`, `/api/admin/images/upload`）
  - 客戶端端點：`/api/client/*`
  - 圖片上傳：`POST /api/admin/images/upload`（需 JWT token）
- **gRPC 服務**：圖片處理自動由 `image-worker` 處理，無需直接呼叫。
- **日誌**：檢查容器日誌以除錯：
  ```bash
  docker logs vue-laravel-archi-backend
  docker logs vue-laravel-archi-image-worker
  ```

## 注意事項

1. **僅限開發環境**：
   - 無 HTTPS，數據以明文傳輸，僅適合內網或本地使用，建議搭配 VPN 或防火牆。
   - 生產環境需加入 HTTPS（如 Let’s Encrypt）。

2. **gRPC 配置**：
   - 確保 `protoc` 和 `grpc_php_plugin` 正確安裝，否則無法生成 stubs。
   - gRPC 服務依賴 Laravel 的 `Storage` 和 `Image` Facade，可能增加耦合，建議未來獨立化。

3. **效能與擴展**：
   - `backend` 容器同時運行 Nginx 和 PHP-FPM，高流量可能有資源競爭。
   - 可考慮將 Nginx 拆到獨立容器，或用 Kubernetes 實現水平擴展。

4. **後續優化建議**：
   - 加入 CI/CD（如 GitHub Actions）自動化測試與部署。
   - 新增 Prometheus + Grafana 監控容器性能。
   - 若需其他非同步任務，考慮恢復 Redis 佇列或使用 Laravel Horizon。

## 常見問題

- **容器啟動失敗**？
  - 檢查 `backend/.env` 是否有正確的 `APP_KEY` 和 `JWT_SECRET`。
  - 確保 Docker 記憶體充足（至少 4GB）。
- **圖片上傳失敗**？
  - 查看 `image-worker` 容器日誌，確認 gRPC 服務運行正常。
  - 檢查 `backend_storage_public` 卷的權限。
- **API 返回 401**？
  - 確認 JWT token 是否有效，必要時重新登入或刷新 token。

