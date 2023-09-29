<?php

namespace App\Http\Controllers;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Elliptic\EC;

use kornrunner\Keccak;

class Web3LoginController extends Controller
{
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['message', 'verify']]);
    }

    public function message(): string
    {
        $nonce = Str::random();
        $message = "Sign this message to confirm you own this wallet address. This action will not cost any gas fees.\n\nNonce: " . $nonce;
        return $message;
    }

    public function verify(Request $request): string
    {
        $result = $this->verifySignature($request->input('message'), $request->input('signature'), $request->input('address'));
        return $result;
    }

    protected function verifySignature(string $message, string $signature, string $address): string
    {
        $hash = Keccak::hash(sprintf("\x19Ethereum Signed Message:\n%s%s", strlen($message), $message), 256);
        $sign = [
            'r' => substr($signature, 2, 64),
            's' => substr($signature, 66, 64),
        ];
        $recid = ord(hex2bin(substr($signature, 130, 2))) - 27;

        if ($recid != ($recid & 1)) {
            return json_encode( [
                'status' => '500',
                'message' => 'Not match',
            ]);
        }

        $pubkey = (new EC('secp256k1'))->recoverPubKey($hash, $sign, $recid);
        $derived_address = '0x' . substr(Keccak::hash(substr(hex2bin($pubkey->encode('hex')), 1), 256), 24);

        if (Str::lower($address) === $derived_address) {
            $token = Auth::login(User::firstOrCreate([
                'eth_address' => $message
            ]));
            return $this->createNewToken($token);
        } else {
            return "{
                'status' => '500',
                'message' => 'Not match' }";
        }
    }

    protected function createNewToken($token){
        return json_encode([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}
