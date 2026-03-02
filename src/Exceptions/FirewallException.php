<?php

declare(strict_types=1);

namespace Laika\Shield\Exceptions;

use RuntimeException;

/**
 * Class FirewallException
 *
 * Thrown when the firewall blocks a request.
 *
 * @package Laika\Shield\Exceptions
 */
class FirewallException extends RuntimeException
{
    public function __construct(
        string $message = 'Request blocked by Laika Shield.',
        private readonly string $rule = 'Unknown',
        private readonly string $clientIp = '',
        int $code = 403,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * The name of the rule that triggered the block.
     */
    public function getRule(): string
    {
        return $this->rule;
    }

    /**
     * The IP address of the blocked client.
     */
    public function getClientIp(): string
    {
        return $this->clientIp;
    }
}
