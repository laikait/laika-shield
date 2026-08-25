<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield;

use Laika\Shield\Exceptions\RateLimitExceededException;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Contract\RuleInterface;
use Laika\Shield\Rules\RequestFilterRule;
use Laika\Shield\Rules\SqlInjectionRule;
use Laika\Shield\Rules\IpVersionRule;
use Laika\Shield\Rules\RateLimitRule;
use Laika\Shield\Rules\CountryRule;
use Laika\Shield\Support\RequestHelper;
use Laika\Shield\Support\IpHelper;
use Laika\Shield\Rules\XssRule;
use Laika\Shield\Rules\IpRule;

/**
 * Class Shield
 *
 * The central firewall engine for the Laika Framework.
 *
 * Usage — quick static API. Shield::boot() takes no arguments; it reads the
 * shared configuration, so configure that first:
 *
 *   ShieldConfig::add('ip', ['blocklist' => ['1.2.3.4']]);
 *   ShieldConfig::add('rate.limit', 'max.hits', 100);
 *
 *   Shield::boot();
 *
 * Usage — an explicit configuration object:
 *
 *   $config = ShieldConfig::make();
 *   $config->ip->blocklist(['1.2.3.4']);
 *
 *   Shield::fromConfig($config)->run();
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
final class Shield
{
    /** @var RuleInterface[] */
    private array $rules = [];

    /** @var bool $trustProxy */
    private bool $trustProxy = false;

    /** @var string[] $trustedProxies */
    private array $trustedProxies = [];

    // -------------------------------------------------------------------------
    // Static Bootstrap
    // -------------------------------------------------------------------------

    /**
     * Boot the firewall from the shared configuration and immediately run it.
     *
     * Configure it first, with either the object API or the static facade:
     *
     *   ShieldConfig::instance()->ip->blocklist(['1.2.3.4']);
     *   ShieldConfig::add('rate.limit', 'max.hits', 30);
     *   Shield::boot();
     *
     * To run an explicit configuration instead, use fromConfig():
     *
     *   Shield::fromConfig($config)->run();
     *
     * @throws FirewallException  When a rule blocks the request.
     * @return void
     */
    public static function boot(): void
    {
        static::fromConfig(ShieldConfig::instance())->run();
    }

    /**
     * Build a configured Shield from a ShieldConfig object WITHOUT running it.
     *
     * Split out of boot() so the config-to-rule wiring can be asserted without
     * evaluating rules against the live request.
     *
     * An array is hydrated over a FRESH set of defaults rather than replacing
     * them, so a partial array keeps every option it does not mention.
     *
     * This deliberately does NOT read the shared instance — it stays free of
     * global state so the wiring can be tested in isolation. Pass
     * ShieldConfig::instance() explicitly if that is what you want.
     *
     * @param ShieldConfig|array<string,mixed> $config
     * @return static
     */
    public static function fromConfig(ShieldConfig|array $config = []): static
    {
        $shield = new static();
        $config = $config instanceof ShieldConfig ? $config : ShieldConfig::fromArray($config);

        $shield->trustProxy($config->trustProxy(), $config->trustedProxies());

        // Country blocking. Skipped unless a database AND a list are configured —
        // building the rule opens a multi-megabyte GeoIP reader, so an unconfigured
        // section must not pay that cost on every request.
        if ($config->country->isConfigured()) {
            $shield->blockCountries(
                $config->country->db(),
                $config->country->blocklist(),
                $config->country->allowlist(),
            );
        }

        // IP blocking / allowlisting
        $shield->blockIps($config->ip->blocklist(), $config->ip->allowlist());

        // IP version filtering. Null means both versions are allowed, which makes
        // the rule a no-op — skip it rather than registering one.
        if ($config->ipVersion() !== null) {
            $shield->requireIpVersion($config->ipVersion());
        }

        // Rate limiting
        $shield->rateLimit(
            $config->rateLimit->maxHits(),
            $config->rateLimit->window(),
            $config->rateLimit->storageDir(),
        );

        // SQL injection detection
        $shield->detectSqlInjection(
            skipKeys: $config->sqlInjection->skipKeys(),
            scanBody: $config->sqlInjection->scanBody(),
            strict:   $config->sqlInjection->strict(),
        );

        // XSS detection
        $shield->detectXss(
            skipKeys:    $config->xss->skipKeys(),
            scanBody:    $config->xss->scanBody(),
            scanHeaders: $config->xss->scanHeaders(),
        );

        // Request filtering
        $shield->filterRequests(
            blockedMethods: $config->requestFilter->blockedMethods(),
            blockedUriPatterns: $config->requestFilter->blockedUriPatterns(),
            blockedUserAgentPatterns: $config->requestFilter->blockedUserAgents(),
            requiredHeaders: $config->requestFilter->requiredHeaders(),
            blockedHeaderValues: $config->requestFilter->blockedHeaderValues(),
            maxContentLength: $config->requestFilter->contentLengthMax(),
            minContentLength: $config->requestFilter->contentLengthMin(),
        );

        return $shield;
    }

    // -------------------------------------------------------------------------
    // Fluent Builder
    // -------------------------------------------------------------------------

    /**
     * Trust proxy headers when resolving the client IP.
     *
     * Always pass $trustedProxies in production. Without it, single-value headers
     * (CF-Connecting-IP, X-Real-IP) are ignored entirely, because a direct client
     * can forge them just as easily as a proxy can set them.
     *
     * @param bool     $trust
     * @param string[] $trustedProxies IPs/CIDRs of your own reverse proxies.
     * @return static
     */
    public function trustProxy(bool $trust = true, array $trustedProxies = []): static
    {
        $this->trustProxy     = $trust;
        $this->trustedProxies = $trustedProxies;
        return $this;
    }

    /**
     * Block and/or allowlist requests by country (ISO 3166-1 alpha-2 codes).
     * Requires a local MaxMind GeoLite2-Country .mmdb file.
     * @param string $mmdb  GeoIP Location DB Path
     * @param string[] $blocklist  Country codes to block (e.g. ['CN', 'RU']).
     * @param string[] $allowlist  When non-empty, ONLY these countries are allowed.
     * @return static
     */
    public function blockCountries(string $mmdb, array $blocklist = [], array $allowlist = []): static
    {
        $this->rules[] = new CountryRule($mmdb, $blocklist, $allowlist, $this->trustProxy, $this->trustedProxies);
        return $this;
    }

    /**
     * Block and/or allowlist IP addresses or CIDR ranges.
     * @param string[] $blocklist
     * @param string[] $allowlist
     * @return static
     */
    public function blockIps(array $blocklist = [], array $allowlist = []): static
    {
        $this->rules[] = new IpRule($blocklist, $allowlist, $this->trustProxy, $this->trustedProxies);
        return $this;
    }

    /**
     * Only allow connections from the given IPs / CIDR ranges.
     * @param string[] $allowlist
     * @return static
     */
    public function allowIps(array $allowlist): static
    {
        return $this->blockIps(allowlist: $allowlist);
    }

    /**
     * Restrict to a specific IP version (4 or 6).
     * @return static
     */
    public function requireIpVersion(int $version): static
    {
        $this->rules[] = new IpVersionRule($version, $this->trustProxy, $this->trustedProxies);
        return $this;
    }

    /**
     * Enable rate limiting.
     * @return static
     */
    public function rateLimit(int $maxHits = 60, int $windowSecs = 60, ?string $storageDir = null): static
    {
        $this->rules[] = new RateLimitRule($maxHits, $windowSecs, $this->trustProxy, $storageDir, 'rl_', $this->trustedProxies);
        return $this;
    }

    /**
     * Enable SQL injection detection.
     * @param string[] $skipKeys
     * @param bool $scanBody Scan raw request body.
     * @param bool $strict When true, also blocks bare SQL keywords with no injection syntax around them. Off by default: it false-positives on ordinary prose.
     * @return static
     */
    public function detectSqlInjection(array $skipKeys = [], bool $scanBody = true, bool $strict = false): static
    {
        $this->rules[] = new SqlInjectionRule($skipKeys, $scanBody, $strict);
        return $this;
    }

    /**
     * Enable XSS detection.
     * @param string[] $skipKeys
     * @param bool $scanBody Default is true
     * @param bool $scanHeaders Default is false
     */
    public function detectXss(array $skipKeys = [], bool $scanBody = true, bool $scanHeaders = false): static
    {
        $this->rules[] = new XssRule($skipKeys, $scanBody, $scanHeaders);
        return $this;
    }

    /**
     * Enable request filtering.
     * @param string[] $blockedMethods
     * @param string[] $blockedUriPatterns
     * @param string[] $blockedUserAgentPatterns
     * @param string[] $requiredHeaders
     * @param array<string,string[]> $blockedHeaderValues
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
    /**
     * Evaluate every registered rule.
     *
     * Terminating the request is deliberately NOT this class's job — a failing rule
     * throws, and the caller (ShieldPipeline) decides how to respond. Keeping exactly
     * one exit point makes the firewall testable.
     *
     * @throws FirewallException
     * @return void
     */
    public function run(): void
    {
        $this->inspect();
    }

    /**
     * @throws FirewallException
     * @return bool Always true; a failing rule throws instead of returning false.
     */
    public function inspect(): bool
    {
        // One input memo per firewall run. The scanning rules share it, but a
        // later run — a new request under a long-running worker such as
        // RoadRunner or Swoole — must never inherit the previous request's body.
        RequestHelper::flush();

        foreach ($this->rules as $rule) {
            if (!$rule->passes()) {
                $this->block($rule);
            }
        }

        return true;
    }

    /**
     * Set the response status/headers for a blocked request and throw.
     *
     * @throws FirewallException
     */
    public function block(RuleInterface $rule): never
    {
        $clientIp = IpHelper::resolve($this->trustProxy, $this->trustedProxies);
        $status   = $rule->statusCode();

        if (!headers_sent()) {
            http_response_code($status);

            // Set Additional Header
            $rule->additionalHeader();
        }

        if ($rule instanceof RateLimitRule) {
            throw new RateLimitExceededException($clientIp, $rule->retryAfter(), $rule->message());
        }

        throw new FirewallException($rule->message(), $clientIp, $status);
    }
}
