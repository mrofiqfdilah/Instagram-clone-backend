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
        // Validate the incoming request data
        $validator = Validator::make($request->all(), [
            'full_name' => 'required|string|max:255', // Full name is required, must be a string and not exceed 255 characters
            'username' => [
                'required',
                'unique:users,username', // Ensure the username is unique
                'regex:/^[a-zA-Z0-9_.]+$/', // Only alphanumeric characters, dots, and underscores allowed
                'min:3', // Minimum 3 characters
                'max:18', // Maximum 18 characters
            ],
            'email' => [
                'required',
                'email:rfc,dns', // Validate the email format
                'unique:users,email', // Ensure the email is unique
                'max:30', // Maximum 30 characters for email
            ],
            'password' => 'required|string|min:8', // Password is required, must be at least 8 characters and confirmed
            'roles' => 'in:user,admin', // The role must be either 'user' or 'admin'
            'image' => 'mimes:jpeg,png,jpg,gif|max:2048'
        ]);

        // If validation fails, return a 422 response with error details
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Invalid field', // General error message
                'errors' => $validator->errors() // Validation errors
            ], 422);
        }

        // Handle image upload if present
        $imagePath = null;
        if ($request->hasFile('image')) {

            // Sanitize the file name
            $originalName = $request->file('image')->getClientOriginalName();
            $sanitizedFileName = Str::slug(pathinfo($originalName, PATHINFO_FILENAME)) . '-' . time() . '.' . $request->file('image')->getClientOriginalExtension();

            // Store the file securely in the 'public' disk
            $imagePath = $request->file('image')->storeAs('Image_Profile', $sanitizedFileName, 'public');
        }

        // Create a new user in the database
        $create_user = User::create([
            'full_name' => $request->full_name,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Hash the password before saving
            'roles' => 'user', // Default role is 'user' (can be adjusted as needed)
            'status' => 'Public',
            'image' => $imagePath // Store the image path or null if no image
        ]);

        // Generate a Sanctum token for the newly created user
        $sanctum_tokens = $create_user->createToken('sanctum_tokens', ['*'], now()->addHours(24))->plainTextToken;

        // Return a success response with the user details and the token
        return response()->json([
            'status' => 'success', // Status of the registration process
            'message' => 'User registered successfully', // Success message
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
                    'image' => $create_user->image ? asset('storage/' . $create_user->image) : null, // Provide URL if image exists
                ],
                'token' => $sanctum_tokens // Generated token for API authentication
            ]
        ], 201); // HTTP Status 201: Created
    }
}
