<?php

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Support\IpHelper;

/**
 * Class IpRule
 *
 * Allows or denies requests based on IP address / CIDR ranges.
 *
 * Resolution order:
 *  1. If an allowlist is configured and the IP is NOT on it → block.
 *  2. If the IP is on the blocklist → block.
 *  3. Otherwise → allow.
 *
 * @package Laika\Shield\Rules
 */
final class IpRule implements RuleInterface
{
    private string $clientIp;
    private string $blockMessage = 'Your IP address has been blocked.';

    /**
     * @param string[] $blocklist   IPs or CIDR ranges to block.
     * @param string[] $allowlist   When non-empty, ONLY these IPs/ranges are allowed.
     * @param bool     $trustProxy  Whether to resolve the client IP from proxy headers.
     */
    public function __construct(
        private readonly array $blocklist = [],
        private readonly array $allowlist = [],
        private readonly bool $trustProxy = false,
    ) {
        $this->clientIp = IpHelper::resolve($this->trustProxy);
    }

    public function passes(): bool
    {
        // Allowlist check — if configured, IP must be on it
        if (!empty($this->allowlist)) {
            if (!IpHelper::inAnyCidr($this->clientIp, $this->allowlist)) {
                $this->blockMessage = "IP {$this->clientIp} is not in the allowlist.";
                return false;
            }
        }

        // Blocklist check
        if (!empty($this->blocklist)) {
            if (IpHelper::inAnyCidr($this->clientIp, $this->blocklist)) {
                $this->blockMessage = "IP {$this->clientIp} is blocked.";
                return false;
            }
        }

        return true;
    }

    public function message(): string
    {
        return $this->blockMessage;
    }

    /**
     * Return the resolved client IP.
     */
    public function clientIp(): string
    {
        return $this->clientIp;
    }
}
