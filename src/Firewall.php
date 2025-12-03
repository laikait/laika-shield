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

class Firewall
{
    public const ACTION_ALLOW = 1;
    public const ACTION_DENY  = 0;

    /** @var Rule[] */
    private array $rules = [];

    private RateLimiter $rateLimiter;

    public function __construct(?RateLimiter $rateLimiter = null)
    {
        $this->rateLimiter = $rateLimiter ?? new RateLimiter();
    }

    public function addRule(Rule $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * Evaluate a request. The $request can be an object that supports ->getServerParams(), ->getHeaderLine(), or an array with similar keys.
     * For frameworks, pass a PSR-7 ServerRequestInterface or adapt accordingly.
     *
     * @param mixed $request
     * @return int ACTION_ALLOW or ACTION_DENY
     */
    public function evaluateRequest($request): int
    {
        $clientIp = $this->detectIp($request);

        // Rate limiter check (deny if over limit)
        if ($this->rateLimiter->isRateLimited($clientIp)) {
            return self::ACTION_DENY;
        }

        foreach ($this->rules as $rule) {
            if ($rule->matches($request, $clientIp)) {
                return $rule->isAllow() ? self::ACTION_ALLOW : self::ACTION_DENY;
            }
        }

        // Default allow
        return self::ACTION_ALLOW;
    }

    private function detectIp($request): string
    {
        // Accept arrays or PSR-7-like objects
        if (is_array($request)) {
            return $request['REMOTE_ADDR'] ?? ($request['client_ip'] ?? '0.0.0.0');
        }

        if (is_object($request)) {
            // PSR-7 ServerRequestInterface
            if (method_exists($request, 'getServerParams')) {
                $sp = $request->getServerParams();
                if (!empty($sp['REMOTE_ADDR'])) return $sp['REMOTE_ADDR'];
            }

            // try common getter
            if (method_exists($request, 'getServerParams')) {
                $sp = $request->getServerParams();
                return $sp['REMOTE_ADDR'] ?? '0.0.0.0';
            }
        }

        return '0.0.0.0';
    }
}
