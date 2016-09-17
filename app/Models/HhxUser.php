<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use DB;

/**
 * @property array  preferences
 * @property int    id
 * @property bool   is_admin
 * @property string lastfm_session_key
 */
class HhxUser extends Model
{
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'users';

    public static function get_username( $credentials ) {
        $complement_field_email = env('COMPLEMENT_FIELD_EMAIL', 'email');
        $complement_field_name  = env('COMPLEMENT_FIELD_NAME', 'name');

        $user = DB::connection('complement')->table('users')
                ->select($complement_field_name)
                ->where($complement_field_email, '=', $credentials['email'])
                ->first();

        return $user->{ $complement_field_name };
    }

    public static function check_login( $credentials ) {
        $complement_field_email = env('COMPLEMENT_FIELD_EMAIL', 'email');
        $complement_field_name  = env('COMPLEMENT_FIELD_NAME', 'name');
        $complement_field_password = env('COMPLEMENT_FIELD_PASSWORD', 'password');

        $user = DB::connection('complement')->table('users')
                ->select([ $complement_field_name, $complement_field_password ])
                ->where($complement_field_email, '=', $credentials['email'])
                ->first();

        if( empty($user) ) {
            return false;
        }

        return self::pass_hash($credentials['password'], $user->{ $complement_field_password });
    }

    private static function pass_hash($lapass, $lapass2){
        $arr = explode(":",$lapass2);
        return (md5($lapass.$arr[1]) === $arr[0])?TRUE:FALSE;
    }
}
