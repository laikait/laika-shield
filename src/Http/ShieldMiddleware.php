<?php

declare(strict_types=1);

namespace Laika\Shield\Http;

use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Exceptions\RateLimitExceededException;
use Laika\Shield\Shield;

/**
 * Class ShieldMiddleware
 * Drop-in Laika MMC middleware that runs the Shield firewall on every request.
 *
 * Register in your Laika application's middleware stack:
 *
 *   // config/shield.php or bootstrap/app.php
 *   \Laika\Shield\Http\ShieldMiddleware::class
 *
 * Or manually:
 *
 *   use Laika\Shield\Http\ShieldMiddleware;
 *
 *   $middleware = new ShieldMiddleware(require 'config/shield.php');
 *   $middleware->handle();
 *
 * @package Laika\Shield\Http
 */
class ShieldMiddleware
{
    /**
     * @param array<string,mixed> $config The Shield configuration array (see Config/shield.php).
     */
    private readonly array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Handle the incoming request.
     * Call this from your Laika middleware pipeline.
     * @throws FirewallException If blocked by a generic rule.
     * @throws RateLimitExceededException If rate limit is exceeded.
     * @return mixed
     */
    public function handle(?callable $next = null): mixed
    {
        try {
            Shield::boot($this->config);
        } catch (FirewallException $e) {
            // FirewallException is already handled inside Shield::block()
            // (headers sent, JSON output written). We just halt here.
            exit;
        }

        // All rules passed — pass control to the next middleware or controller.
        if ($next !== null) {
            return $next();
        }

        return null;
    }
}
