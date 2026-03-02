<?php

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Support\IpHelper;
use Laika\Shield\Support\RateLimiter;

/**
 * Class RateLimitRule
 *
 * Blocks clients that send more than $maxHits requests within a $windowSecs window.
 * Uses a file-based store by default (no external dependencies).
 *
 * @package Laika\Shield\Rules
 */
final class RateLimitRule implements RuleInterface
{
    private readonly string $clientIp;
    private int $retryAfter = 0;

    /**
     * @param int         $maxHits     Maximum number of requests allowed per window.
     * @param int         $windowSecs  Window size in seconds.
     * @param bool        $trustProxy  Whether to resolve the client IP from proxy headers.
     * @param string|null $storageDir  Directory for rate-limit files. Defaults to sys_get_temp_dir().
     * @param string      $keyPrefix   Prefix for rate-limit storage keys.
     */
    public function __construct(
        private readonly int $maxHits = 60,
        private readonly int $windowSecs = 60,
        private readonly bool $trustProxy = false,
        private readonly ?string $storageDir = null,
        private readonly string $keyPrefix = 'rl_',
    ) {
        $this->clientIp = IpHelper::resolve($this->trustProxy);
    }

    public function passes(): bool
    {
        $limiter = new RateLimiter($this->storageDir);
        $key     = $this->keyPrefix . $this->clientIp;

        if ($limiter->tooMany($key, $this->maxHits, $this->windowSecs)) {
            $this->retryAfter = $limiter->retryAfter($key);
            return false;
        }

        return true;
    }

    public function message(): string
    {
        return sprintf(
            'Too many requests from %s. Please wait %d second(s) before retrying.',
            $this->clientIp,
            $this->retryAfter,
        );
    }

    /**
     * Number of seconds the client should wait before sending the next request.
     * Only meaningful after {@see passes()} has returned false.
     */
    public function retryAfter(): int
    {
        return $this->retryAfter;
    }
}
