<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Contract\RuleInterface;
use Laika\Shield\Support\IpHelper;

/**
 * Class IpVersionRule
 *
 * Allows you to restrict requests to a specific IP version (4 or 6).
 * Useful if your application intentionally does not serve IPv6 traffic, or vice-versa.
 *
 * @package Laika\Shield\Rules
 */
final class IpVersionRule implements RuleInterface
{
    private string $clientIp;
    private string $blockMessage = '';
    private int $statusCode = 200;

    /**
     * @param int|null $allowedVersion  Pass 4 to allow only IPv4, 6 to allow only IPv6,
     *                                  or null to allow both (rule is effectively a no-op).
     * @param bool     $trustProxy      Whether to resolve the client IP from proxy headers.
     * @param string[] $trustedProxies IPs/CIDRs of your own reverse proxies.
     */
    public function __construct(
        private readonly int|null $allowedVersion = null,
        private readonly bool $trustProxy = false,
        private readonly array $trustedProxies = [],
    ) {
        $this->clientIp = IpHelper::resolve($this->trustProxy, $this->trustedProxies);
    }

    public function passes(): bool
    {
        if ($this->allowedVersion === null) {
            return true;
        }

        $version = IpHelper::version($this->clientIp);

        if ($version === null) {
            $this->blockMessage = "Could Not Detect IP Version for Address: [{$this->clientIp}].";
            $this->statusCode = 403;
            return false;
        }

        if ($version !== $this->allowedVersion) {
            $this->blockMessage = "IPv{$version} Connections Are Not Allowed (Only IPv{$this->allowedVersion} Is Permitted).";
            $this->statusCode = 403;
            return false;
        }

        return true;
    }

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
}
