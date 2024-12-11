<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class CheckAuthorization
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Check if the Authorization header exists
        if (!$request->hasHeader('Authorization')) {
            return response()->json([
                'status' => 'error',
                'message' => 'Authorization header is missing'
            ], Response::HTTP_UNAUTHORIZED);
        }

        // Extract token from the Authorization header
        $authorizationHeader = $request->header('Authorization');
        $token = str_replace('Bearer ', '', $authorizationHeader);

        // Check if the token is empty
        if (empty($token)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token is missing'
            ], Response::HTTP_UNAUTHORIZED);
        }

        // Attempt to authenticate using the token
        try {
            // Attempt to validate the token (you can use your own logic or package here)
            if (!Auth::guard('sanctum')->user()) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Invalid or expired token'
                ], Response::HTTP_UNAUTHORIZED);
            }

            // Continue the request processing if valid
            return $next($request);
        } catch (\Exception $e) {
            // Handle exceptions like token validation failure
            return response()->json([
                'status' => 'error',
                'message' => 'Token validation failed: ' . $e->getMessage()
            ], Response::HTTP_UNAUTHORIZED);
        }
    }
}
