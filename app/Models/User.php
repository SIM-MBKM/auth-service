<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;

class User extends Model
{
    use HasUuids;

    protected $connection = 'auth';
    protected $table = 'users';

    protected $fillable = [
        'name',
        'email',
        'sso_id',
        'role',
        'no_wa',
    ];

    protected $hidden = [
        'remember_token',
    ];
}
