<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserIdentity extends Model
{
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
