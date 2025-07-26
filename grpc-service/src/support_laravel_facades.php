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
