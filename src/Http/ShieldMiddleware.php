<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Http;

use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Exceptions\RateLimitExceededException;
use Laika\Shield\Shield;
use Closure;

/**
 * Class ShieldMiddleware
 * Drop-in Laika MMC middleware that runs the Shield firewall on every request.
 *
 * Register in your Laika application's middleware stack:
 *
 *   // config/shield.php or bootstrap/app.php
 *   \Laika\Shield\Http\ShieldMiddleware::class
 *
 * Or manually:
 *
 *   use Laika\Shield\Http\ShieldMiddleware;
 *   use Laika\Shield\Config;
 *
 *   $middleware = new ShieldMiddleware(Config::get());
 *   $middleware->handle();
 *
 * @package Laika\Shield\Http
 * @deprecated
 */
class ShieldMiddleware
{
    /**
     * @param array<string,mixed> $config The Shield configuration array (see Config/shield.php).
     */
    private readonly array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Handle the incoming request.
     * Call this from your Laika middleware pipeline.
     * @throws FirewallException If blocked by a generic rule.
     * @throws RateLimitExceededException If rate limit is exceeded.
     */
    public function handle(Closure $next, array $params)
    {
        try {
            Shield::boot($this->config);
        } catch (FirewallException $e) {
            unset($params);
            $next(['blocked' => $e->getMessage()]);
        }

        return $next($params);
    }
}
