<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class AccessKey extends Model
{
    use HasUuids;

    protected $connection = 'auth';
    protected $table = 'access_keys';

    protected $fillable = [
        'id',
        'user_id',
        'key_hash',
        'description',
        'scopes',
        'is_active',
        'expires_at',
        'last_used_at',
    ];

    protected $casts = [
        'scopes' => 'array',
        'is_active' => 'boolean',
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}