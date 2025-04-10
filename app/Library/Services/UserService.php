<?php

namespace App\Libraries\Services;

use Illuminate\Support\Facades\Http;
use SimMbkm\ModService\Service as BaseService;

class UserService extends BaseService
{
    protected $baseUri;

    public function __construct()
    {
        $this->baseUri = config('services.user_management_service.base_uri');
    }
}
