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

class RateLimiter
{
    private int $limit;
    private int $windowSeconds;
    private array $storage = [];

    public function __construct(int $limit = 100, int $windowSeconds = 60)
    {
        $this->limit = $limit;
        $this->windowSeconds = $windowSeconds;
    }

    public function isRateLimited(string $ip): bool
    {
        $now = time();
        if (!isset($this->storage[$ip])) {
            $this->storage[$ip] = ['count' => 1, 'start' => $now];
            return false;
        }

        $entry = &$this->storage[$ip];
        if ($now - $entry['start'] > $this->windowSeconds) {
            $entry['count'] = 1;
            $entry['start'] = $now;
            return false;
        }

        $entry['count']++;
        return $entry['count'] > $this->limit;
    }
}
