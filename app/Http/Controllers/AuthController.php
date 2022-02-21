<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $rules = array(
            'name' => 'required|string|max:225',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:5|confirmed',
            // 'role' => 'required|max:1',
        );

        $cek = Validator::make($request->all(),$rules);

        if($cek->fails()){
            $errorString = implode(",",$cek->messages()->all());
            return response()->json([
                'message' => $errorString
            ], 401);
        }else{
            $user = User::create([
                'name' => $request->name,
                'password' => Hash::make($request->password),
                'email' => $request->email,
            ]);

            if ($user) {
                $user->assignRole('user');
                $role = "user";
            }else{
                return response()->json([
                    'status'    => 'Failed',
                    'message'   => 'gagal',
                ],422);
            }
        
            $token = $user->createToken($user->$email.'token-name')->plainTextToken;

            return response()->json([
                'status'    => 'Success',
                'message'   => 'Berhasil Membuat Akun',
                'role'      => $role,
                'user'      => $user,
                'token'     => $token,
            ], 200);
        }
    }
    public function login(Request $request)
    {
        $validate = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);

        if($validate->fails()){
            $respons = [
                'status'    => 'error',
                'msg'       => 'Validator error',
                'errors'    => $validate->errors(),
                'content'   => null,
            ];
            return response()->json($respons, 200);
        }else{
            $credentials    = request(['email', 'password']);
            $credentials    = Arr::add($credentials, 'status', 'aktif');
            if(!Auth::attempt($credentials)){
                $respons = [
                    'status'    => 'error',
                    'msg'       => 'Unathorized',
                    'errors'    => null,
                    'content'   => null,
                ];
                return response()->json($respons, 401);
            }

            $user   = User::where('email', $request->email)->first();
            if(! Hash::check($request->password, $user->password, [])){
                throw new Exception('Error in login');
            }

            $tokenResult = $user->createToken($user->$email.'token-auth')->plainTextToken;
             $respons = [
                    'status'    => 'success',
                    'msg'       => 'Login Successfully', 
                    'token'     => $tokenResult,
                    'errors'    => null,
                    'content'   => [
                        'status_code'   => 200,
                        'token_type'    => 'Bearer',
                    ],
                ];
                return response()->json($respons, 200);
        }
    }
}