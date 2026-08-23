<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Class FirewallException
 *
 * Thrown when the firewall blocks a request.
 *
 * {@see getMessage()} stays human-readable. Use {@see payload()} when you need the
 * JSON body for the block response — do not parse getMessage().
 *
 * @package Laika\Shield\Exceptions
 */
class FirewallException extends RuntimeException
{
    public function __construct(
        string $message = 'Request blocked by Laika Shield.',
        private readonly string $clientIp = '',
        int $code = 403,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * The block response as a JSON string.
     *
     * @return string
     */
    public function payload(): string
    {
        return (string) json_encode($this->toArray(), JSON_UNESCAPED_SLASHES);
    }

    /**
     * The block response as a structured array.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'status'  => $this->getCode(),
            'message' => $this->getMessage(),
            'ip'      => $this->clientIp,
        ];
    }
}
