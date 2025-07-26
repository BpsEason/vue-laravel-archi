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
