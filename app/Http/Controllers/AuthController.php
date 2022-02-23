<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Validator;
use Hash;
use Auth;
use HashRoles;

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
                'password' => bcrypt($request->password),
                'email' => $request->email,
                'role' => 1
            ]);

            if ($user->role == 1) {
                $user->assignRole('user');
             
            }else{
                return response()->json([
                    'status'    => 'Failed',
                    'message'   => 'gagal',
                    'user'      => $user
                    
                ],422);
            }
        
            $token = $user->createToken('token-name')->plainTextToken;
            $role = $user->getRoleNames();

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
        $rules = array(
            'email' => 'required|string|email|',
            'password' => 'required|string|min:5',
        );

        $cek = Validator::make($request->all(),$rules);

        if($cek->fails()){
            $errorString = implode(",",$cek->messages()->all());
            return response()->json([
                'message' => $errorString
            ], 401);
        }else{
            $user = User::where('email',$request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'message' => 'Unauthorized'
                ],401);
            }
        
            $token = $user->createToken('token-name')->plainTextToken;
            $roles = $user->getRoleNames();

            return response()->json([
                'status'    => 'Success',
                'message'   => 'Berhasil Login',
                'role'      => $roles,
                'user'      => $user,
                'token'     => $token,
            ], 200);
        }
    }
    public function registerAdmin(Request $request)
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
                'password' => bcrypt($request->password),
                'email' => $request->email,
            ]);

            if ($user) {
                $user->assignRole('admin');
                $role = "admin";
            }else{
                return response()->json([
                    'status'    => 'Failed',
                    'message'   => 'gagal',
                ],422);
            }
        
            $token = $user->createToken('token-name')->plainTextToken;

            return response()->json([
                'status'    => 'Success',
                'message'   => 'Berhasil Membuat Akun',
                'role'      => $role,
                'user'      => $user,
                'token'     => $token,
            ], 200);
        }
    }
}