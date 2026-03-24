<?php

declare(strict_types=1);

namespace Laika\Shield;

use Laika\Shield\Interfaces\FirewallInterface;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Rules\RequestFilterRule;
use Laika\Shield\Rules\SqlInjectionRule;
use Laika\Shield\Rules\IpVersionRule;
use Laika\Shield\Rules\RateLimitRule;
use Laika\Shield\Rules\CountryRule;
use Laika\Shield\Support\IpHelper;
use Laika\Shield\Rules\XssRule;
use Laika\Shield\Rules\IpRule;

/**
 * Class Shield
 *
 * The central firewall engine for the Laika Framework.
 *
 * Usage — quick static API:
 *
 *   Shield::boot([
 *       'ip'            => ['blocklist' => ['1.2.3.4']],
 *       'rate.limit'    => ['max.hits' => 100, 'window' => 60],
 *       'sql.injection' => true,
 *       'xss'           => true,
 *   ]);
 *
 * Usage — fluent builder API:
 *
 *   (new Shield())
 *       ->blockIps(['1.2.3.4', '10.0.0.0/8'])
 *       ->allowIps(['203.0.113.0/24'])
 *       ->rateLimit(100, 60)
 *       ->detectSqlInjection()
 *       ->detectXss()
 *       ->filterRequests(blockedMethods: ['TRACE'])
 *       ->run();
 *
 * @package Laika\Shield
 */
class Shield implements FirewallInterface
{
    /** @var RuleInterface[] */
    private array $rules = [];

    /** @var bool $trustProxy */
    private bool $trustProxy = false;

    // -------------------------------------------------------------------------
    // Static Bootstrap
    // -------------------------------------------------------------------------

    /**
     * Boot the firewall from a configuration array and immediately run it.
     * If no config is passed, defaults are loaded from Config::get().
     *
     * @param  array<string,mixed> $config  See shield.php config for all options.
     * @throws FirewallException
     */
    public static function boot(array $config = []): void
    {
        $shield = new self();

        // Fall back to Config class defaults when no array is provided
        $config = empty($config) ? Config::get() : $config;

        $trustProxy = (bool) ($config['trust.proxy'] ?? false);
        $shield->trustProxy($trustProxy);

        // Country blocking
        if (!empty($config['country'])) {
            $c = $config['country'];
            if (!empty($c['db'])) {
                $shield->blockCountries($c['db'], $c['blocklist'] ?? [], $c['allowlist'] ?? []);
            }
        }

        // IP blocking / allowlisting
        if (!empty($config['ip'])) {
            $ip = $config['ip'];
            $shield->blockIps($ip['blocklist'] ?? [], $ip['allowlist'] ?? []);
        }

        // IP version filtering
        if (!empty($config['ip.version'])) {
            $shield->requireIpVersion((int) $config['ip.version']);
        }

        // Rate limiting
        if (!empty($config['rate.limit'])) {
            $rl = $config['rate.limit'];
            $shield->rateLimit(
                (int) ($rl['max.hits'] ?? 60),
                (int) ($rl['window'] ?? 60),
                $rl['storage.dir'] ?? null,
            );
        }

        // SQL injection detection
        if (!empty($config['sql.injection'])) {
            $sqli = is_array($config['sql.injection']) ? $config['sql.injection'] : [];
            $shield->detectSqlInjection(
                $sqli['skip.keys'] ?? [],
                (bool) ($sqli['scan.body'] ?? true),
                (bool) ($sqli['strict'] ?? true),
            );
        }

        // XSS detection
        if (!empty($config['xss'])) {
            $xss = is_array($config['xss']) ? $config['xss'] : [];
            $shield->detectXss(
                $xss['skip.keys'] ?? [],
                (bool) ($xss['scan.headers'] ?? false),
                (bool) ($xss['scan.body'] ?? true),
            );
        }

        // Request filtering
        if (!empty($config['request.filter'])) {
            $rf = $config['request.filter'];
            $shield->filterRequests(
                blockedMethods: $rf['blocked.methods'] ?? [],
                blockedUriPatterns: $rf['blocked.uri.patterns'] ?? [],
                blockedUserAgentPatterns: $rf['blocked.user.agents'] ?? [],
                requiredHeaders: $rf['headers.required'] ?? [],
                blockedHeaderValues: $rf['blocked.header.values'] ?? [],
                maxContentLength: $rf['content.length.max'] ?? null,
                minContentLength: $rf['content.length.min'] ?? null,
            );
        }

        $shield->run();
    }

    // -------------------------------------------------------------------------
    // Fluent Builder
    // -------------------------------------------------------------------------

    public function trustProxy(bool $trust = true): static
    {
        $this->trustProxy = $trust;
        return $this;
    }

    /**
     * Block and/or allowlist requests by country (ISO 3166-1 alpha-2 codes).
     * Requires a local MaxMind GeoLite2-Country .mmdb file.
     *
     * @param string[] $blocklist  Country codes to block (e.g. ['CN', 'RU']).
     * @param string[] $allowlist  When non-empty, ONLY these countries are allowed.
     */
    public function blockCountries(string $dbPath, array $blocklist = [], array $allowlist = []): static
    {
        $this->rules[] = new CountryRule($dbPath, $blocklist, $allowlist, $this->trustProxy);
        return $this;
    }

    /**
     * Block and/or allowlist IP addresses or CIDR ranges.
     *
     * @param string[] $blocklist
     * @param string[] $allowlist
     */
    public function blockIps(array $blocklist = [], array $allowlist = []): static
    {
        $this->rules[] = new IpRule($blocklist, $allowlist, $this->trustProxy);
        return $this;
    }

    /**
     * Only allow connections from the given IPs / CIDR ranges.
     *
     * @param string[] $allowlist
     */
    public function allowIps(array $allowlist): static
    {
        return $this->blockIps(allowlist: $allowlist);
    }

    /**
     * Restrict to a specific IP version (4 or 6).
     */
    public function requireIpVersion(int $version): static
    {
        $this->rules[] = new IpVersionRule($version, $this->trustProxy);
        return $this;
    }

    /**
     * Enable rate limiting.
     */
    public function rateLimit(int $maxHits = 60, int $windowSecs = 60, ?string $storageDir = null): static
    {
        $this->rules[] = new RateLimitRule($maxHits, $windowSecs, $this->trustProxy, $storageDir);
        return $this;
    }

    /**
     * Enable SQL injection detection.
     *
     * @param string[] $skipKeys
     * @param bool     $scanBody  Scan raw request body.
     * @param bool     $strict    When true, also blocks standalone DML keywords
     *                            (SELECT/INSERT/UPDATE/DELETE/DROP).
     */
    public function detectSqlInjection(array $skipKeys = [], bool $scanBody = true, bool $strict = true): static
    {
        $this->rules[] = new SqlInjectionRule($skipKeys, $scanBody, $strict);
        return $this;
    }

    /**
     * Enable XSS detection.
     *
     * @param string[] $skipKeys
     */
    public function detectXss(array $skipKeys = [], bool $scanHeaders = false, bool $scanBody = true): static
    {
        $this->rules[] = new XssRule($skipKeys, $scanHeaders, $scanBody);
        return $this;
    }

    /**
     * Enable request filtering.
     *
     * @param string[]                $blockedMethods
     * @param string[]                $blockedUriPatterns
     * @param string[]                $blockedUserAgentPatterns
     * @param string[]                $requiredHeaders
     * @param array<string,string[]>  $blockedHeaderValues
     */
    public function filterRequests(
        array $blockedMethods = [],
        array $blockedUriPatterns = [],
        array $blockedUserAgentPatterns = [],
        array $requiredHeaders = [],
        array $blockedHeaderValues = [],
        ?int $maxContentLength = null,
        ?int $minContentLength = null,
    ): static {
        $this->rules[] = new RequestFilterRule(
            $blockedMethods,
            $blockedUriPatterns,
            $blockedUserAgentPatterns,
            $requiredHeaders,
            $blockedHeaderValues,
            $maxContentLength,
            $minContentLength,
        );

        return $this;
    }

    /**
     * Register a custom rule.
     */
    public function addRule(RuleInterface $rule): static
    {
        $this->rules[] = $rule;
        return $this;
    }

    // -------------------------------------------------------------------------
    // Execution
    // -------------------------------------------------------------------------

    /**
     * Evaluate all registered rules. Blocks the request if any rule fails.
     *
     * @throws FirewallException
     */
    public function run(): void
    {
        if (!$this->inspect()) {
            exit;
        }
    }

    public function inspect(): bool
    {
        foreach ($this->rules as $rule) {
            if (!$rule->passes()) {
                // $this->block($rule->message());
                $this->block($rule);
            }
        }

        return true;
    }

    // public function block(string $reason = 'Forbidden'): never
    public function block(RuleInterface $rule): never
    {
        $clientIp   = IpHelper::resolve($this->trustProxy);

        if (!headers_sent()) {
            http_response_code($rule->statusCode());

            // Set Content Type Header
            header('Content-Type: application/json; charset=UTF-8');

            // Set Additional Header
            $rule->additionalHeader();
        }

        echo json_encode([
            'error'     =>  true,
            'status'    =>  $rule->statusCode(),
            'message'   =>  $rule->message(),
            'ip'        =>  $clientIp
        ], JSON_PRETTY_PRINT);

        throw new FirewallException($rule->message(), get_class($rule), $clientIp, $rule->statusCode());
    }
}
