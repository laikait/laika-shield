<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Pipeline;

// Deny Direct Access
defined('APP_PATH') || http_response_code(403).die('403 Direct Access Denied!');

use Laika\Route\Interfaces\PipelineInterface;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Exceptions\RateLimitExceededException;
use Laika\Shield\Config;
use Laika\Shield\Shield;

/**
 * Class ShieldPipeline
 *
 * Runs the Shield firewall as the first pipeline in the route chain.
 *
 * Register it ahead of every other pipeline — it is only a firewall if nothing
 * else has run yet.
 *
 * A blocked request emits its response and terminates. It deliberately does not
 * hand control back to the chain:
 *
 *   return $next()        runs the rest of the chain
 *   return $next(false)   halts the chain, but leaves no way to emit a body
 *   return 'something'    runs the rest of the chain, replacing only the controller
 *
 * The third is the trap: a "blocked" request would still execute every downstream
 * pipeline — auth, logging, database writes — with just the controller swapped out.
 * So a block echoes its payload and dies.
 *
 * @package Laika\Shield\Pipeline
 */
class ShieldPipeline implements PipelineInterface
{
    private readonly Config $config;

    /**
     * With no argument — which is how the framework auto-registers this pipeline —
     * the shared configuration is used, so whatever the application set up with
     * Config::add() or Config::instance() applies.
     *
     * Note the array branch: options are applied on top of the shared instance
     * with fill(), which MUTATES global configuration. That is intentional for the
     * single-source model, but it is a side effect worth knowing about if you
     * construct pipelines more than once in a process.
     *
     * @param Config|array<string,mixed> $config Shield configuration.
     */
    public function __construct(Config|array $config = [])
    {
        $this->config = match (true) {
            $config instanceof Config => $config,
            $config === []            => Config::instance(),
            default                   => Config::instance()->fill($config),
        };
    }

    /**
     * Handle the incoming request.
     *
     * @param callable $next
     * @param array<string,mixed> $params
     * @return ?string
     */
    public function handle(callable $next, array &$params): ?string
    {
        try {
            Shield::fromConfig($this->config)->run();
        } catch (FirewallException $e) {
            // Status code and headers were already set by Shield::block().
            $this->respond($e);
        }

        return $next();
    }

    /**
     * Emit the block response and terminate the request.
     *
     * Split out from handle() so tests can override it — a bare die() cannot be
     * asserted in-process, and running the whole suite in separate processes to
     * work around that is slow and brittle.
     *
     * @param FirewallException $e
     * @return never
     */
    protected function respond(FirewallException $e): never
    {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');

            if ($e instanceof RateLimitExceededException) {
                header('Retry-After: ' . $e->getRetryAfter());
            }
        }

        echo $e->payload();
        die;
    }
}
