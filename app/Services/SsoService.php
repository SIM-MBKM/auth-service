<?php

namespace App\Services;

use Dptsi\Sso\Models\User as SsoUser;
use Dptsi\Sso\Models\Role;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Its\Sso\OpenIDConnectClient;
use Laravel\Socialite\Contracts\User as SocialiteUserContract;

class SsoService
{
    /**
     * Redirect to the SSO provider
     */
    public function redirect()
    {
        try {
            // Create OpenID client manually
            $oidc = new OpenIDConnectClient(
                config('openid.provider'),
                config('openid.client_id'),
                config('openid.client_secret')
            );

            $oidc->setRedirectURL(config('openid.redirect_uri'));
            $oidc->addScope(config('openid.scope'));

            if (strtolower(config('app.env')) != 'production' && strtolower(config('app.env')) != 'prod') {
                $oidc->setVerifyHost(false);
                $oidc->setVerifyPeer(false);
            }

            // This will handle the redirect
            $oidc->authenticate();
        } catch (Exception $e) {
            Log::error("SSO redirect error: {$e->getMessage()}", [
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Process the callback from SSO provider
     * 
     * @param Request $request
     * @return array Contains user and token info
     */
    public function processCallback(Request $request)
    {
        try {
            // Create OpenID client
            $oidc = new OpenIDConnectClient(
                config('openid.provider'),
                config('openid.client_id'),
                config('openid.client_secret')
            );

            $oidc->setRedirectURL(config('openid.redirect_uri'));
            $oidc->addScope(config('openid.scope'));

            if (strtolower(config('app.env')) != 'production' && strtolower(config('app.env')) != 'prod') {
                $oidc->setVerifyHost(false);
                $oidc->setVerifyPeer(false);
            }

            // Process authentication with the code parameter
            // Note: The authenticate method handles the code from the request automatically
            $oidc->authenticate();

            // Get user info from the provider
            $userInfo = $oidc->requestUserInfo();

            // Create a SsoUser object
            $user = $this->createSsoUserFromUserInfo($userInfo);

            // Get the tokens
            $idToken = $oidc->getIdToken();
            $accessToken = $oidc->getAccessToken();

            return [
                'user' => $user,
                'id_token' => $idToken,
                'access_token' => $accessToken
            ];
        } catch (Exception $e) {
            Log::error("Manual SSO callback processing error: {$e->getMessage()}", [
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Create a SsoUser object from user info
     */
    private function createSsoUserFromUserInfo($userInfo)
    {
        try {
            // Create user with all available fields
            $user = new SsoUser(
                $userInfo->sub,
                $userInfo->name ?? null,
                $userInfo->nickname ?? null,
                $userInfo->picture ?? null,
                $userInfo->gender ?? null,
                isset($userInfo->birthdate) ? new Carbon($userInfo->birthdate) : null,
                $userInfo->zoneinfo ?? null,
                $userInfo->locale ?? null,
                $userInfo->preferred_username ?? null,
                $userInfo->email ?? null,
                $userInfo->email_verified ?? null,
                $userInfo->alternate_email ?? null,
                $userInfo->alternate_email_verified ?? null,
                $userInfo->phone ?? null,
                $userInfo->phone_verified ?? null,
                isset($userInfo->resource) ? json_decode(json_encode($userInfo->resource), true) : null,
                $userInfo->integra_id ?? null
            );

            // Process groups if they exist
            if (isset($userInfo->group)) {
                Log::debug('Processing user groups', [
                    'count' => count($userInfo->group)
                ]);

                foreach ($userInfo->group as $group) {
                    if (in_array($group->group_name, config('openid.allowed_roles', []))) {
                        $user->addUserRole(new Role($group->group_name, null, null, null));
                    }
                }
            }

            // Process roles if they exist
            if (isset($userInfo->role)) {
                Log::debug('Processing user roles', [
                    'count' => count($userInfo->role)
                ]);

                foreach ($userInfo->role as $role) {
                    if (in_array($role->role_name, config('openid.allowed_roles', []))) {
                        $newRole = new Role(
                            $role->role_name,
                            $role->org_id,
                            $role->org_name,
                            isset($role->expired_at) ? new Carbon($role->expired_at) : null
                        );
                        $user->addUserRole($newRole);
                        if ($role->is_default === '1')
                            $user->setActiveRole($newRole);
                    }
                }
            }

            // Set default active role if not already set
            if (!empty($user->getRoles()) && empty($user->getActiveRole()))
                $user->setActiveRole($user->getRoles()[0] ?? null);

            return $user;
        } catch (Exception $e) {
            Log::error("Error creating SSO user: {$e->getMessage()}", [
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Convert SSO User to a format compatible with SocialiteService
     */
    public function convertToSocialiteUser($ssoUser, $token)
    {
        return new class($ssoUser, $token) implements SocialiteUserContract {
            private $ssoUser;
            public $token;
            public $refreshToken = null;
            public $expiresIn = null;

            public function __construct($ssoUser, $token)
            {
                $this->ssoUser = $ssoUser;
                $this->token = $token;
            }

            public function getId()
            {
                return $this->ssoUser->getId();
            }

            public function getNickname()
            {
                return $this->ssoUser->getNickname();
            }

            public function getName()
            {
                return $this->ssoUser->getName();
            }

            public function getEmail()
            {
                return $this->ssoUser->getEmail();
            }

            public function getAvatar()
            {
                return $this->ssoUser->getPicture();
            }

            public function getRaw()
            {
                // Return all available user data
                return [
                    'id' => $this->ssoUser->getId(),
                    'name' => $this->ssoUser->getName(),
                    'email' => $this->ssoUser->getEmail(),
                    'picture' => $this->ssoUser->getPicture(),
                    'nickname' => $this->ssoUser->getNickname(),
                    'gender' => $this->ssoUser->getGender(),
                    'roles' => $this->ssoUser->getRoles(),
                    'active_role' => $this->ssoUser->getActiveRole(),
                ];
            }

            public function getAccessTokenResponseBody()
            {
                return [];
            }

            // Methods required by the interface
            public function setToken($token)
            {
                $this->token = $token;
                return $this;
            }

            public function setRefreshToken($refreshToken)
            {
                $this->refreshToken = $refreshToken;
                return $this;
            }

            public function setExpiresIn($expiresIn)
            {
                $this->expiresIn = $expiresIn;
                return $this;
            }
        };
    }

    /**
     * Logout from SSO
     */
    public function logout($token = null)
    {
        try {
            $oidc = new OpenIDConnectClient(
                config('openid.provider'),
                config('openid.client_id'),
                config('openid.client_secret')
            );

            if (strtolower(config('app.env')) != 'production' && strtolower(config('app.env')) != 'prod') {
                $oidc->setVerifyHost(false);
                $oidc->setVerifyPeer(false);
            }

            // Sign out using the provided token
            $oidc->signOut($token, config('openid.post_logout_redirect_uri'));
        } catch (Exception $e) {
            Log::error("SSO logout error: {$e->getMessage()}", [
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
