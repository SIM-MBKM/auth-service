<?php

use Illuminate\Database\Eloquent\Model;

class Session extends Model
{
    protected $keyType = 'string';
    public $incrementing = false;

    // protected $casts = [
    //     'id' => 'uuid',
    //     'user_id' => 'uuid',
    //     'last_activity_at' => 'datetime',
    //     'expires_at' => 'datetime',
    // ];
}
