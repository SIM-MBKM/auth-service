<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class UserIdentity extends Model
{
    use HasUuids;

    protected $connection = 'auth';
    protected $table = 'user_identities';

     protected $fillable = [
        'user_id',
        'provider',
        'provider_user_id',
        'access_token',
        'refresh_token',
        'expires_at',
        'provider_data',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'provider_data' => 'array', //JSON payload
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
