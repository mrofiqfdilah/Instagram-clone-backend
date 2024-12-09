<?php

use App\Http\Controllers\API\Auth\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('signup', [AuthController::class, 'SignUp']);
Route::post('signin', [AuthController::class, 'SignIn']);
Route::post('signout', [AuthController::class, 'SignOut'])->middleware(['check.auth']);
