<?php

namespace App\Services;

use Exception;
use Illuminate\Support\Facades\Log;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Exchange\AMQPExchangeType;
use PhpAmqpLib\Message\AMQPMessage;

class QueueService
{
    protected $connection;
    protected $channel;
    protected $config;
    protected $shouldCloseConnection = true;

    public function __construct()
    {
        try {
            $this->config = config('rabbitmq.connections.user_sync');

            Log::debug('Initializing RabbitMQ connection', [
                'host' => $this->config['host'],
                'port' => $this->config['port'],
                'vhost' => $this->config['vhost']
            ]);

            $this->connection = new AMQPStreamConnection(
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
                false, // keepalive
                60 // heartbeat
            );

            $this->channel = $this->connection->channel();

            Log::info('RabbitMQ connection established', [
                'channel_id' => $this->channel->getChannelId()
            ]);
        } catch (Exception $e) {
            Log::error('RabbitMQ connection failed', [
                'error' => $e->getMessage(),
                'config' => $this->config
            ]);
            throw $e;
        }
    }

    public function publishUserEvent(string $eventType, array $payload): void
    {
        try {
            $this->declareExchange();
            $this->publishSingleMessage($eventType, $payload);
        } catch (Exception $e) {
            Log::error('Failed to publish message', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        } finally {
            if ($this->shouldCloseConnection) {
                $this->safeShutdown();
            }
        }
    }

    public function publishUserEventsBatch(array $events): void
    {
        try {
            $this->shouldCloseConnection = false;
            $this->declareExchange();

            foreach ($events as $event) {
                $this->publishSingleMessage($event['type'], $event['payload']);
            }
        } catch (Exception $e) {
            Log::error('Failed to publish batch messages', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        } finally {
            $this->safeShutdown();
        }
    }

    protected function declareExchange(): void
    {
        Log::debug('Declaring exchange', [
            'exchange' => 'user_events',
            'type' => AMQPExchangeType::TOPIC
        ]);

        $this->channel->exchange_declare(
            'user_events',
            AMQPExchangeType::TOPIC,
            false, // passive
            true, // durable
            false // auto_delete
        );
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
            'message' => $messageBody
        ]);

        $this->channel->basic_publish($message, 'user_events', $routingKey);

        Log::info('Message published successfully', [
            'event_type' => $eventType,
            'payload_size' => strlen($messageBody)
        ]);
    }

    protected function safeShutdown(): void
    {
        try {
            if ($this->channel && $this->channel->is_open()) {
                Log::debug('Closing channel', [
                    'channel_id' => $this->channel->getChannelId()
                ]);
                $this->channel->close();
            }

            if ($this->connection && $this->connection->isConnected()) {
                Log::debug('Closing connection');
                $this->connection->close();
            }
        } catch (Exception $e) {
            Log::error('Error during shutdown', [
                'error' => $e->getMessage()
            ]);
        }
    }

    public function __destruct()
    {
        $this->safeShutdown();
    }
}
