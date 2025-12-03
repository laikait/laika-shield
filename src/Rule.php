<?php

/**
 * Laika Shield
 * Author: Showket Ahmed
 * Email: riyadhtayf@gmail.com
 * License: MIT
 * This file is part of the Laika MMC Framework.
 * For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Laika\Shield;

class Rule
{
    private bool $allow = false;
    private ?string $ip = null;
    private ?string $cidr = null;
    private $callback = null; // callable

    public function allow(): self
    {
        $this->allow = true;
        return $this;
    }

    public function deny(): self
    {
        $this->allow = false;
        return $this;
    }

    public function ip(string $ip): self
    {
        $this->ip = $ip;
        return $this;
    }

    public function cidr(string $cidr): self
    {
        $this->cidr = $cidr;
        return $this;
    }

    public function callback(callable $cb): self
    {
        $this->callback = $cb;
        return $this;
    }

    public function matches($request, string $clientIp): bool
    {
        if ($this->ip !== null) {
            if ($this->ip === $clientIp) return true;
        }

        if ($this->cidr !== null) {
            if (IpMatcher::inCidr($clientIp, $this->cidr)) return true;
        }

        if ($this->callback !== null) {
            try {
                return (bool) call_user_func($this->callback, $request);
            } catch (\Throwable $e) {
                // if callback fails, do not match
                return false;
            }
        }

        return false;
    }

    public function isAllow(): bool
    {
        return $this->allow;
    }
}
