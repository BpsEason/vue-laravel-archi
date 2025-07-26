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
