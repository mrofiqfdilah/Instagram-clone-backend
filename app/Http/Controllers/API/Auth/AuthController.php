<?php

namespace App\Http\Controllers\API\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    /**
     * Handle user registration.
     *
     * This method receives the user data, validates the input,
     * creates a new user, generates a Sanctum token, and returns
     * the user's details along with the generated token.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function SignUp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'full_name' => 'required|string|max:100',
            'username' => [
                'required',
                'unique:users,username',
                'regex:/^[a-zA-Z0-9_.]+$/',
                'min:3',
                'max:18',
            ],
            'email' => [
                'required',
                'email:rfc,dns',
                'unique:users,email',
                'max:30',
            ],
            'password' => 'required|string|min:8',
            'roles' => 'in:user,admin',
            'image' => 'mimes:jpeg,png,jpg|max:2048'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Invalid field',
                'errors' => $validator->errors()
            ], 422);
        }

        $imagePath = null;
        if ($request->hasFile('image')) {
            $originalName = $request->file('image')->getClientOriginalName();
            $sanitizedFileName = Str::slug(pathinfo($originalName, PATHINFO_FILENAME)) . '-' . time() . '.' . $request->file('image')->getClientOriginalExtension();
            $imagePath = $request->file('image')->storeAs('Image_Profile', $sanitizedFileName, 'public');
        }

        $create_user = User::create([
            'full_name' => $request->full_name,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'roles' => 'user',
            'status' => 'Public',
            'image' => $imagePath
        ]);

        $sanctum_tokens = $create_user->createToken('sanctum_tokens', ['*'], now()->addHours(24))->plainTextToken;

        return response()->json([
            'status' => 'success',
            'message' => 'User registered successfully',
            'data' => [
                'user' => [
                    'id' => $create_user->id,
                    'full_name' => $create_user->full_name,
                    'username' => $create_user->username,
                    'email' => $create_user->email,
                    'roles' => $create_user->roles,
                    'status' => $create_user->status,
                    'created_at' => $create_user->created_at,
                    'updated_at' => $create_user->updated_at,
                    'image' => $create_user->image ? asset('storage/' . $create_user->image) : null,
                ],
                'token' => $sanctum_tokens
            ]
        ], 201);
    }


    /**
     * Handle user login.
     *
     * This method receives the user credentials (username and password), validates the input,
     * attempts to authenticate the user, and if successful, generates a Sanctum token for the user.
     * The response includes the user's role and the generated token for authentication.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function SignIn(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Invalid field',
                'errors' => $validator->errors()
            ], 422);
        }

        $credentials = $request->only('username', 'password');

        if (Auth::attempt($credentials)) {
            $userLogin = Auth::user();

            $sanctum_tokens = $userLogin->createToken('sanctum_tokens', ['*'], now()->addHours(24))->plainTextToken;


            return response()->json([
                'status' => 'success',
                'message' => 'User login successfully',
                'data' => [
                    'id' => $userLogin->id,
                    'full_name' => $userLogin->full_name,
                    'roles' => $userLogin->roles,
                    'token' => $sanctum_tokens
                ],
            ], 200);
        }

        return response()->json([
            'message' => 'Invalid username or password',
        ], 401);
    }

    public function SignOut(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'User signed out successfully'
        ], 200);
    }
}
