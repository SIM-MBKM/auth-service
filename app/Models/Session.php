<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Session extends Model
{
    protected $connection = 'auth';
    protected $table = 'sessions';

    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'user_id',
        'token_hash',
        'payload',
        'user_agent',
        'ip_address',
        'last_activity',
        'expires_at',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'last_activity' => 'integer',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
