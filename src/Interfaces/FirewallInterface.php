<?php

declare(strict_types=1);

namespace Laika\Shield\Interfaces;

/**
 * Interface FirewallInterface
 *
 * Core contract that all firewall implementations must fulfill.
 *
 * @package Laika\Shield\Interfaces
 */
interface FirewallInterface
{
    /**
     * Run the firewall against the current request.
     * Returns true if the request is allowed, false if it should be blocked.
     */
    public function inspect(): bool;

    /**
     * Block the current request with an appropriate HTTP response.
     */
    public function block(string $reason = 'Forbidden'): never;
}
