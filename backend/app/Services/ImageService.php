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
