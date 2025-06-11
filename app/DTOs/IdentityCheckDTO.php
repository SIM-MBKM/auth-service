<?php

namespace App\DTOs;

use InvalidArgumentException;

class IdentityCheckDTO
{
    public function __construct(
        public readonly string $email
    ) {}

    public static function fromEmail(string $email): self
    {
        $decodedEmail = urldecode($email);
        if ($decodedEmail === false) {
            throw new InvalidArgumentException('Invalid URL encoded email');
        }

        // Validate email format and security
        validator(
            ['email' => $decodedEmail],
            [
                'email' => [
                    'required',
                    'email:rfc,dns,spoof',
                    'max:255',
                    function ($attribute, $value, $fail) {
                        // Check for potentially misleading characters
                        if (preg_match('/\p{Cyrillic}|\p{Greek}|\p{Arabic}/u', $value)) {
                            $fail('The email contains potentially misleading characters.');
                        }

                        // Check for suspicious character combinations
                        if (preg_match('/[А-Яа-я].*@.*\.com$/u', $value)) {
                            $fail('The email contains suspicious character combinations.');
                        }
                    }
                ],
            ]
        )->validate();

        // Sanitize email
        $sanitizedEmail = filter_var($decodedEmail, FILTER_SANITIZE_EMAIL);
        if ($decodedEmail !== $sanitizedEmail) {
            throw new InvalidArgumentException('Invalid email format after sanitization');
        }

        // Check allowed domains
        $emailParts = explode('@', $decodedEmail);
        if (count($emailParts) !== 2) {
            throw new InvalidArgumentException('Invalid email format');
        }

        $domain = $emailParts[1];
        $allowedDomains = config('emaildomain.allowed', []);

        if (!in_array($domain, $allowedDomains)) {
            throw new InvalidArgumentException('Email domain not allowed');
        }

        if ($domain === 'student.its.ac.id' && $emailParts[0]) {
            if (!preg_match('/^5017|5025\d{6}$/', $emailParts[0])) {
                throw new InvalidArgumentException('Student is not from allowed department.');
            }
        }

        return new self(email: $decodedEmail);
    }
}
