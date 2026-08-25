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
 * @method static void add(string $key, mixed $subKeyOrValue, mixed $value = null)
 * @method static bool has(string $key)
 * @method static array keys()
 * @method static mixed get(?string $key = null)
 * @method static void reset()
 * @method static \Laika\Shield\ShieldConfig instance()
 * @method static \Laika\Shield\Config\IpConfig ip()
 * @method static \Laika\Shield\Config\RateLimitConfig rateLimit()
 * @method static \Laika\Shield\Config\SqlInjectionConfig sqlInjection()
 * @method static \Laika\Shield\Config\XssConfig xss()
 * @method static \Laika\Shield\Config\RequestFilterConfig requestFilter()
 * @method static \Laika\Shield\Config\CountryConfig country()
 * @method static \Laika\Shield\ShieldConfig make()
 */
class ShieldConfig extends Relay
{
    protected static function getRelayAccessor(): string
    {
        return 'shield.config';
    } 
}