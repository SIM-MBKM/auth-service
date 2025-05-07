<?php

namespace App\Providers;

use App\Services\AuthService;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use App\Services\QueueService;
use App\Services\SsoService;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(QueueService::class, function ($app) {
            return new QueueService();
        });
        $this->app->singleton(SsoService::class, function ($app) {
            return new SsoService();
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
            $event->extendSocialite('google', \SocialiteProviders\Google\GoogleExtendSocialite::class);
        });
    }
}
