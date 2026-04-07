<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Detectors\GeoIpDetector;
use Laika\Shield\Support\IpHelper;

/**
 * Class CountryRule
 *
 * Blocks or allowlists requests based on the client's country,
 * resolved from a local MaxMind GeoLite2-Country database.
 *
 * Blocklist: deny requests from these countries.
 * Allowlist: when non-empty, ONLY allow requests from these countries.
 *
 * Country codes must be ISO 3166-1 alpha-2 (e.g. 'US', 'CN', 'RU').
 *
 * @package Laika\Shield\Rules
 */
final class CountryRule implements RuleInterface
{
    private string $blockMessage = '';
    private string $clientIp;

    /**
     * @param string   $dbPath      Absolute path to GeoLite2-Country.mmdb.
     * @param string[] $blocklist   ISO country codes to block.
     * @param string[] $allowlist   When non-empty, ONLY these countries are allowed.
     * @param bool     $trustProxy  Whether to resolve the real IP from proxy headers.
     */
    public function __construct(
        private readonly string $mmdb,
        private readonly array $blocklist = [],
        private readonly array $allowlist = [],
        private readonly bool $trustProxy = false,
    ) {
        $this->clientIp = IpHelper::resolve($this->trustProxy);
    }

    public function passes(): bool
    {
        $detector = new GeoIpDetector($this->mmdb, $this->clientIp);
        $country  = $detector->detect();

        // Private/loopback IPs won't resolve — let them through
        if ($country === null) {
            return true;
        }

        $country = strtoupper($country);

        // Allowlist check — if configured, country must be on it
        if (!empty($this->allowlist)) {
            $allowlist = array_map('strtoupper', $this->allowlist);
            if (!in_array($country, $allowlist, true)) {
                $this->blockMessage = "Access From Country [{$detector->name()}] Is Not Allowed.";
                return false;
            }
        }

        // Blocklist check
        if (!empty($this->blocklist)) {
            $blocklist = array_map('strtoupper', $this->blocklist);
            if (in_array($country, $blocklist, true)) {
                $this->blockMessage = "Access From Country [{$detector->name()}] Is Blocked.";
                return false;
            }
        }

        return true;
    }

    public function message(): string
    {
        return $this->blockMessage;
    }

    public function statusCode(): int
    {
        return 403;
    }

    public function additionalHeader(): void
    {
        return;
    }
}
