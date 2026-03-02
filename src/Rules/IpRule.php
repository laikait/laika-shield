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
    private string $blockMessage = 'Your IP Address Has Been Blocked.';
    private int $statusCode = 200;

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

    /**
     * Check Rule Passes
     * @return bool
     */
    public function passes(): bool
    {
        // Allowlist check — if configured, IP must be on it
        if (!empty($this->allowlist)) {
            if (!IpHelper::inAnyCidr($this->clientIp, $this->allowlist)) {
                $this->blockMessage = "IP [{$this->clientIp}] Is Not In The Allowlist.";
                $this->statusCode = 403;
                return false;
            }
        }

        // Blocklist check
        if (!empty($this->blocklist)) {
            if (IpHelper::inAnyCidr($this->clientIp, $this->blocklist)) {
                $this->blockMessage = "IP [{$this->clientIp}] Is Blocked.";
                $this->statusCode = 403;
                return false;
            }
        }

        return true;
    }

    /**
     * Return Message
     * @return string
     */
    public function message(): string
    {
        return $this->blockMessage;
    }

    /**
     * Return Response Code
     * @return int
     */
    public function statusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Set Addetional Header if Required. Example: header('Refresh: 0');
     * @return void
     */
    public function additionalHeader(): void
    {
        return;
    }

    /**
     * Return The Resolved Client IP.
     * @return string
     */
    public function clientIp(): string
    {
        return $this->clientIp;
    }
}
