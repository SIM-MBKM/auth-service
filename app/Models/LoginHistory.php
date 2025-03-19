<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class LoginHistory extends Model
{
    use HasUuids;

    protected $connection = 'auth';
    protected $table = 'login_histories';

    protected $fillable = [
        'id',
        'user_id',
        'auth_method',
        'ip_address',
        'user_agent',
        'success',
        'failure_reason',
    ];

    protected $casts = [
        'success' => 'boolean',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
