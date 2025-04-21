<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class UserIdentity extends Model
{
    use HasUuids;

    protected $connection = 'auth_management';
    protected $table = 'user_identities';

    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';

    protected static function boot()
    {
        parent::boot();
        static::creating(function ($model) {
            $model->id = (string) \Illuminate\Support\Str::uuid();
        });
    }

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
