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

class Middleware
{
    private Firewall $firewall;

    public function __construct(Firewall $fw)
    {
        $this->firewall = $fw;
    }

    /**
     * Example for frameworks: a simple callable middleware compatible with many frameworks.
     * The provided $next callable should be invoked only when allowed.
     */
    public function __invoke($request, $response, callable $next)
    {
        $action = $this->firewall->evaluateRequest($request);
        if ($action === Firewall::ACTION_DENY) {
            // modify response (psr-7 style) or return early
            if (is_object($response) && method_exists($response, 'withStatus')) {
                return $response->withStatus(403);
            }

            // fallback: return simple array
            return ['status' => 403, 'body' => 'Forbidden'];
        }

        return $next($request, $response);
    }
}