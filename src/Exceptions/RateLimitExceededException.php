<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Exceptions;

/**
 * Class RateLimitExceededException
 *
 * Thrown when a client exceeds the configured rate limit.
 *
 * @package Laika\Shield\Exceptions
 */
class RateLimitExceededException extends FirewallException
{
    public function __construct(
        string $clientIp = '',
        private readonly int $retryAfter = 60,
        ?\Throwable $previous = null
    ) {
        parent::__construct(
            'Too many requests. Please try again later.',
            'RateLimitRule',
            $clientIp,
            429,
            $previous
        );
    }

    /**
     * Number of seconds the client should wait before retrying.
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
