<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Relay;

use Laika\Core\Relay\Relay;

class Config extends Relay
{
    /**
     * @method static void add(string $key, mixed $subKeyOrValue, mixed $value = null)
     * @method static void has(string $key)
     * @method static array keys()
     * @method static mixed get(?string $key = null)
     * @method static void reset()
     */
    public static function getRelayAccessor(): string
    {
        return 'config';
    }
}
