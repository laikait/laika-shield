<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Service;

use Laika\Relay\Relay;

/**
 * @method static static trustProxy(bool $trust = true, array $trustedProxies = [])
 * @method static static blockCountries(string $mmdb, array $blocklist = [], array $allowlist = [])
 * @method static static blockIps(array $blocklist = [], array $allowlist = [])
 * @method static static allowIps(array $allowlist)
 * @method static static requireIpVersion(int $version)
 * @method static static rateLimit(int $maxHits = 60, int $windowSecs = 60, ?string $storageDir = null)
 * @method static static detectSqlInjection(array $skipKeys = [], bool $scanBody = true, bool $strict = false)
 * @method static static detectXss(array $skipKeys = [], bool $scanBody = true, bool $scanHeaders = false)
 * @method static static filterRequests(array $blockedMethods = [], array $blockedUriPatterns = [], array $blockedUserAgentPatterns = [], array $requiredHeaders = [], array $blockedHeaderValues = [], ?int $maxContentLength = null, ?int $minContentLength = null)
 * @method static static addRule(RuleInterface $rule)
 * @method static bool inspect()
 * @method static void run()
 * @method static never block(RuleInterface $rule)
 * @method static void boot()
 * @method static static fromConfig(\Laika\Shield\Config|array $config = [])
 */
class Shield extends Relay
{
    protected static function getRelayAccessor(): string
    {
        return 'shield';
    } 
}