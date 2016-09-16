<?php

namespace App\Http\Controllers\API;

use App\Http\Requests\API\UserLoginRequest;
use App\Http\Controllers\API\AuthController as Authcontroler;
use App\Models\User;
use Exception;
use JWTAuth;
use Log;
use Tymon\JWTAuth\Exceptions\JWTException;
use DB;
use Auth;
use Hash;

class ComplementAuthController extends Authcontroler
{
    /**
     * Log a user in.
     *
     * @param UserLoginRequest $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function complement_login_check(UserLoginRequest $request)
    {
        $credentials = $request->only('email', 'password');
        DB::setDefaultConnection('complement');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                DB::setDefaultConnection('mysql');
                return $this->login($request);
            }
        } catch (JWTException $e) {
            Log::error($e);

            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        DB::setDefaultConnection('mysql');
        $local_token = JWTAuth::attempt($credentials);
        if( !$local_token ) {
            $this->import_user();
            $token = JWTAuth::attempt($request->only('email', 'password'));
        }

        return response()->json(compact('token'));
    }

    private function import_user() {
        $complement_field_email = env('COMPLEMENT_FIELD_EMAIL', 'email');
        $complement_field_name  = env('COMPLEMENT_FIELD_NAME', 'name');
        DB::setDefaultConnection('complement');

        $userdata = User::where($complement_field_email, $credentials['email'])->first();

        DB::setDefaultConnection('mysql');
        User::create([
            'name'     => $userdata[ $complement_field_name ],
            'email'    => $credentials['email'],
            'password' => Hash::make($request->password),
        ]);
    }
}