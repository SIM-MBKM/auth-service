<?php

namespace App\Services;

use Exception;
use Illuminate\Support\Facades\Log;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Exchange\AMQPExchangeType;
use PhpAmqpLib\Message\AMQPMessage;

class QueueService
{
    protected static $connection;
    protected static $channel;
    protected $config;
    protected static $exchangeDeclared = false;

    public function __construct()
    {
        $this->config = config('rabbitmq.connections.user_sync');
        $this->ensureConnection();
    }

    protected function ensureConnection(): void
    {
        if (
            static::$connection && static::$connection->isConnected() &&
            static::$channel && static::$channel->is_open()
        ) {
            return; // Connection already exists and is healthy
        }

        try {
            Log::debug('Initializing RabbitMQ connection', [
                'host' => $this->config['host'],
                'port' => $this->config['port'],
                'vhost' => $this->config['vhost']
            ]);

            static::$connection = new AMQPStreamConnection(
                $this->config['host'],
                $this->config['port'],
                $this->config['user'],
                $this->config['password'],
                $this->config['vhost'],
                false, // insist
                'AMQPLAIN', // login method
                null, // login response
                'en_US', // locale
                10.0, // connection timeout
                10.0, // read/write timeout
                null, // context
                true, // keepalive - IMPORTANT: Enable this
                60 // heartbeat
            );

            static::$channel = static::$connection->channel();
            static::$exchangeDeclared = false; // Reset exchange declaration

            Log::info('RabbitMQ connection established', [
                'channel_id' => static::$channel->getChannelId()
            ]);
        } catch (Exception $e) {
            Log::error('RabbitMQ connection failed', [
                'error' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    public function publishUserEvent(string $eventType, array $payload): void
    {
        try {
            $this->ensureConnection();
            $this->declareExchange();
            $this->publishSingleMessage($eventType, $payload);

            Log::info('Message publishing completed', [
                'event_type' => $eventType
            ]);
        } catch (Exception $e) {
            Log::error('Failed to publish message', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
        // NOTE: Don't close connection here - keep it alive for reuse
    }

    public function publishUserEventsBatch(array $events): void
    {
        try {
            $this->ensureConnection();
            $this->declareExchange();

            foreach ($events as $event) {
                $this->publishSingleMessage($event['type'], $event['payload']);
            }

            Log::info('Batch messages published', [
                'count' => count($events)
            ]);
        } catch (Exception $e) {
            Log::error('Failed to publish batch messages', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    protected function declareExchange(): void
    {
        if (static::$exchangeDeclared) {
            return;
        }

        Log::debug('Declaring exchange', [
            'exchange' => 'user_events',
            'type' => AMQPExchangeType::TOPIC
        ]);

        static::$channel->exchange_declare(
            'user_events',
            AMQPExchangeType::TOPIC,
            false, // passive
            true, // durable
            false // auto_delete
        );

        static::$exchangeDeclared = true;
        Log::debug('Exchange declared successfully');
    }

    protected function publishSingleMessage(string $eventType, array $payload): void
    {
        $messageBody = json_encode([
            'event_type' => $eventType,
            'payload' => $payload,
            'timestamp' => now()->toISOString()
        ]);

        $message = new AMQPMessage($messageBody, [
            'delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT,
            'content_type' => 'application/json'
        ]);

        $routingKey = 'user.' . $eventType;

        Log::debug('Publishing message', [
            'exchange' => 'user_events',
            'routing_key' => $routingKey,
            'message_size' => strlen($messageBody)
        ]);

        static::$channel->basic_publish($message, 'user_events', $routingKey);

        Log::info('Message published successfully', [
            'event_type' => $eventType,
            'payload_size' => strlen($messageBody)
        ]);
    }

    public static function closeConnection(): void
    {
        try {
            if (static::$channel && static::$channel->is_open()) {
                Log::debug('Closing channel');
                static::$channel->close();
            }

            if (static::$connection && static::$connection->isConnected()) {
                Log::debug('Closing connection');
                static::$connection->close();
            }

            static::$channel = null;
            static::$connection = null;
            static::$exchangeDeclared = false;
        } catch (Exception $e) {
            Log::error('Error during shutdown', [
                'error' => $e->getMessage()
            ]);
        }
    }

    public function __destruct()
    {
        // Don't auto-close the static connection in destructor
        // Let it be reused across multiple instances
    }
}
