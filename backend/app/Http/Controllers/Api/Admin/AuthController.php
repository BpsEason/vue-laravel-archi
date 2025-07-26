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
