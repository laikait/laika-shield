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

class IpMatcher
{
    public static function inCidr(string $ip, string $cidr): bool
    {
        // Support format "a.b.c.d/n"
        if (strpos($cidr, '/') === false) return false;
        list($subnet, $mask) = explode('/', $cidr, 2);
        $mask = (int) $mask;

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) return false;

        $maskLong = -1 << (32 - $mask);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}