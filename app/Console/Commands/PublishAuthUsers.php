<?php

namespace App\Console\Commands;

use App\Services\QueueService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class PublishAuthUsers extends Command
{
    protected $signature = 'auth:publish-users';
    protected $description = 'Publish auth users to RabbitMQ queue with role assignments';

    public function handle()
    {
        $this->info('Publishing auth users to RabbitMQ...');

        try {
            // Get all users based on the seeder structure
            $userIds = [
                '22af29d8-1e05-4d2b-b237-70955e0af315', // Muhammad Rafif
                '70c7739f-7812-4386-9665-b00af9d095bf', // Muhammad Risqullah
                '55c69fa3-c4de-4390-b36c-8343712c08bf', // Dr. Ahmad Fauzi
                '6d587477-431e-4de2-b0d6-f48e382c8811', // Dr. Siti Aminah
                'c409a413-896f-4c37-8bf9-e41925f326c2'  // Partner Representative
            ];

            $users = DB::connection('auth_management')->table('users')
                ->whereIn('id', $userIds)
                ->get();

            // Get role IDs from user_management database
            $mahasiswaRoleId = DB::connection('user_management')->table('roles')
                ->where('name', 'MAHASISWA')
                ->value('id');

            $dosenPemonevRoleId = DB::connection('user_management')->table('roles')
                ->where('name', 'DOSEN PEMONEV')
                ->value('id');

            $dosenPembimbingRoleId = DB::connection('user_management')->table('roles')
                ->where('name', 'DOSEN PEMBIMBING')
                ->value('id');

            $partnerRoleId = DB::connection('user_management')->table('roles')
                ->where('name', 'MITRA')
                ->value('id');

            // Prepare batch events with role assignments
            $events = [];
            foreach ($users as $user) {
                if (!$user) continue;

                // Determine the appropriate role based on user ID
                $payload = [
                    'auth_user_id' => $user->id
                ];

                // Add role_id to payload based on user
                switch ($user->id) {
                    case '22af29d8-1e05-4d2b-b237-70955e0af315':
                        // Muhammad Rafif - will be auto-assigned as admin by user service
                        // No role_id needed in payload
                        break;

                    case '70c7739f-7812-4386-9665-b00af9d095bf':
                        // Muhammad Risqullah - assign as mahasiswa
                        if ($mahasiswaRoleId) {
                            $payload['role_id'] = $mahasiswaRoleId;
                        }
                        break;

                    case '55c69fa3-c4de-4390-b36c-8343712c08bf':
                        // Dr. Ahmad Fauzi - assign as dosen pemonev
                        if ($dosenPemonevRoleId) {
                            $payload['role_id'] = $dosenPemonevRoleId;
                        }
                        break;

                    case '6d587477-431e-4de2-b0d6-f48e382c8811':
                        // Dr. Siti Aminah - assign as dosen pembimbing
                        if ($dosenPembimbingRoleId) {
                            $payload['role_id'] = $dosenPembimbingRoleId;
                        }
                        break;

                    case 'c409a413-896f-4c37-8bf9-e41925f326c2':
                        // Partner Representative - assign as partner/mitra
                        if ($partnerRoleId) {
                            $payload['role_id'] = $partnerRoleId;
                        }
                        break;
                }

                $events[] = [
                    'type' => 'created',
                    'payload' => $payload
                ];
            }

            // Create QueueService instance
            $queueService = new QueueService();

            // Create progress bar
            $bar = $this->output->createProgressBar(count($events));
            $bar->start();

            // Publish all events in batch
            $queueService->publishUserEventsBatch($events);

            $bar->finish();
            $this->newLine(2);
            $this->info('All users published to RabbitMQ successfully!');

            // Display published users for verification
            $this->newLine();
            $this->table(
                ['ID', 'Name', 'Email', 'Role', 'Role ID'],
                $users->map(function ($user) use ($events) {
                    $role = match ($user->id) {
                        '22af29d8-1e05-4d2b-b237-70955e0af315' => 'Admin (auto-assigned)',
                        '70c7739f-7812-4386-9665-b00af9d095bf' => 'MAHASISWA',
                        '55c69fa3-c4de-4390-b36c-8343712c08bf' => 'DOSEN PEMONEV',
                        '6d587477-431e-4de2-b0d6-f48e382c8811' => 'DOSEN PEMBIMBING',
                        'c409a413-896f-4c37-8bf9-e41925f326c2' => 'MITRA',
                        default => 'Unknown'
                    };

                    // Find the event for this user to get the role_id
                    $eventPayload = collect($events)->first(function ($event) use ($user) {
                        return $event['payload']['auth_user_id'] === $user->id;
                    });

                    $roleId = $eventPayload['payload']['role_id'] ?? 'No role_id (auto-assigned)';

                    return [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $role,
                        'role_id' => $roleId
                    ];
                })->toArray()
            );

            return 0;
        } catch (\Exception $e) {
            $this->error('Failed to publish users: ' . $e->getMessage());
            Log::error('Failed to publish auth users', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return 1;
        }
    }
}
