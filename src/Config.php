<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield;

use Laika\Shield\Config\CountryConfig;
use Laika\Shield\Config\IpConfig;
use Laika\Shield\Config\RateLimitConfig;
use Laika\Shield\Config\RequestFilterConfig;
use Laika\Shield\Config\SectionConfig;
use Laika\Shield\Config\SqlInjectionConfig;
use Laika\Shield\Config\XssConfig;

/**
 * Class Config
 *
 * The Shield configuration as an object graph. Every option carries its default
 * on the property that holds it, so a Config is complete the moment it exists —
 * there is no config file to publish.
 *
 * Config is a SINGLETON. The constructor is not public, because a detached
 * config that Shield::boot() cannot see is a trap, not a feature.
 *
 * Normal use — configure the shared instance, then boot:
 *
 *   Config::instance()
 *       ->trustProxy(true)
 *       ->trustedProxies(['10.0.0.0/8']);
 *
 *   Config::instance()->ip->blocklist(['1.2.3.4', '10.0.0.0/8']);
 *   Config::instance()->rateLimit->maxHits(30)->window(120);
 *
 *   Shield::boot();
 *
 * Detached use — build one explicitly and run it yourself:
 *
 *   $config = Config::make();
 *   $config->xss->skipKeys(['content']);
 *
 *   Shield::fromConfig($config)->run();
 *
 * Because options are set individually, a partial configuration merges over the
 * defaults instead of replacing them: setting request.filter's content.length.max
 * leaves its blocked.methods untouched.
 *
 * The static API (add/get/has/keys/reset) is kept as a compatibility facade over
 * a shared instance and still speaks dotted keys and arrays.
 *
 * @package Laika\Shield
 */
class Config
{
    private static ?Config $instance = null;

    public readonly IpConfig $ip;

    public readonly RateLimitConfig $rateLimit;

    public readonly SqlInjectionConfig $sqlInjection;

    public readonly XssConfig $xss;

    public readonly RequestFilterConfig $requestFilter;

    public readonly CountryConfig $country;

    /**
     * Trust proxy headers when resolving the client IP.
     */
    private bool $trustProxy = false;

    /**
     * IPs / CIDR ranges of YOUR OWN reverse proxies. Required for trustProxy to be
     * safe: forwarded headers are attacker-controlled, so Shield only believes
     * CF-Connecting-IP / X-Real-IP when the connecting peer is listed here.
     *
     * @var string[]
     */
    private array $trustedProxies = [];

    /**
     * Restrict to a single IP version: 4, 6, or null for both.
     */
    private ?int $ipVersion = null;

    /**
     * Not public: Config is a singleton. Use Config::instance() for the shared
     * configuration that Shield::boot() reads, or Config::make() / fromArray()
     * for a detached instance to hand to Shield::fromConfig().
     *
     * A public constructor let callers build a config that boot() could never
     * see, which silently did nothing.
     */
    protected function __construct()
    {
        $this->ip            = new IpConfig();
        $this->rateLimit     = new RateLimitConfig();
        $this->sqlInjection  = new SqlInjectionConfig();
        $this->xss           = new XssConfig();
        $this->requestFilter = new RequestFilterConfig();
        $this->country       = new CountryConfig();
    }

    ######################################################################
    /*========================= SCALAR OPTIONS =========================*/
    ######################################################################

    /**
     * @return static|bool
     */
    public function trustProxy(?bool $value = null): static|bool
    {
        if (func_num_args() === 0) {
            return $this->trustProxy;
        }

        $this->trustProxy = (bool) $value;
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function trustedProxies(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->trustedProxies;
        }

        $this->trustedProxies = $value ?? [];
        return $this;
    }

    /**
     * Pass 4 for IPv4 only, 6 for IPv6 only, or null to allow both.
     *
     * @return static|int|null
     */
    public function ipVersion(?int $value = null): static|int|null
    {
        if (func_num_args() === 0) {
            return $this->ipVersion;
        }

        $this->ipVersion = $value;
        return $this;
    }

    ######################################################################
    /*========================= ARRAY INTEROP ==========================*/
    ######################################################################

    /**
     * A new, DETACHED configuration carrying the defaults.
     *
     * This is not the shared instance — Shield::boot() will not see it. Pass it
     * to Shield::fromConfig() explicitly, or use Config::instance() instead.
     *
     * @return static
     */
    public static function make(): static
    {
        return new static();
    }

    /**
     * Build a DETACHED Config from a dotted-key array, starting from the defaults.
     *
     * Only the keys present are applied, so a partial array merges rather than
     * replaces. Unknown keys are ignored.
     *
     * @param array<string,mixed> $config
     * @return static
     */
    public static function fromArray(array $config): static
    {
        return static::make()->fill($config);
    }

    ######################################################################
    /*======================= SECTION ACCESSORS ========================*/
    ######################################################################

    /*
     * These always resolve the SHARED instance — the one Shield::boot() reads.
     *
     * If you are holding a detached config from Config::make(), reach its
     * sections through the object instead ($config->rateLimit); these accessors
     * will not see it.
     */

    /**
     * IP blocking / allowlisting on the shared configuration.
     */
    public static function ip(): IpConfig
    {
        return static::instance()->ip;
    }

    /**
     * Rate limiting on the shared configuration.
     */
    public static function rateLimit(): RateLimitConfig
    {
        return static::instance()->rateLimit;
    }

    /**
     * SQL injection detection on the shared configuration.
     */
    public static function sqlInjection(): SqlInjectionConfig
    {
        return static::instance()->sqlInjection;
    }

    /**
     * XSS detection on the shared configuration.
     */
    public static function xss(): XssConfig
    {
        return static::instance()->xss;
    }

    /**
     * Request filtering on the shared configuration.
     */
    public static function requestFilter(): RequestFilterConfig
    {
        return static::instance()->requestFilter;
    }

    /**
     * Country blocking on the shared configuration.
     */
    public static function country(): CountryConfig
    {
        return static::instance()->country;
    }

    /**
     * Apply a dotted-key array over this instance.
     *
     * @param array<string,mixed> $config
     * @return static
     */
    public function fill(array $config): static
    {
        foreach (self::SCALARS as $key => $accessor) {
            // array_key_exists, not isset — an explicit null is a value.
            if (array_key_exists($key, $config)) {
                $this->{$accessor}($config[$key]);
            }
        }

        foreach (self::SECTIONS as $key => $property) {
            if (array_key_exists($key, $config) && is_array($config[$key])) {
                $this->{$property}->fill($config[$key]);
            }
        }

        return $this;
    }

    /**
     * The whole configuration as a dotted-key array.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = [];

        foreach (self::SCALARS as $key => $accessor) {
            $out[$key] = $this->{$accessor}();
        }

        foreach (self::SECTIONS as $key => $property) {
            $out[$key] = $this->{$property}->toArray();
        }

        return $out;
    }

    /**
     * Resolve a section object by its dotted config key.
     */
    public function section(string $key): ?SectionConfig
    {
        $property = self::SECTIONS[$key] ?? null;

        return $property === null ? null : $this->{$property};
    }

    ######################################################################
    /*==================== STATIC COMPATIBILITY API ====================*/
    ######################################################################

    /**
     * Add or merge a value into the shared configuration.
     *
     * Two-argument call:   Config::add('ip', ['blocklist' => [...]])
     * Three-argument call: Config::add('rate.limit', 'max.hits', 30)
     *
     * @param string $key Config key
     * @param mixed $subKeyOrValue Sub key, or the value for a two-argument call
     * @param mixed $value Value for a three-argument call. Default is null.
     * @return void
     */
    public static function add(string $key, mixed $subKeyOrValue, mixed $value = null): void
    {
        $config = self::instance();

        // Three-argument form: set one option inside a section.
        if ($value !== null) {
            $section = $config->section($key);

            if ($section === null || !is_string($subKeyOrValue) || !$section->hasKey($subKeyOrValue)) {
                return;
            }

            $existing = $section->option($subKeyOrValue);

            // Arrays accumulate, matching the documented behaviour of this API.
            $section->option(
                $subKeyOrValue,
                is_array($existing) && is_array($value) ? array_merge($existing, $value) : $value
            );

            return;
        }

        // Two-argument form: a scalar option, or a whole section.
        if (isset(self::SCALARS[$key])) {
            $config->{self::SCALARS[$key]}($subKeyOrValue);
            return;
        }

        $section = $config->section($key);

        if ($section !== null && is_array($subKeyOrValue)) {
            $section->fill($subKeyOrValue);
        }
    }

    /**
     * Check whether a top-level key exists in the current config.
     * @return bool
     */
    public static function has(string $key): bool
    {
        return isset(self::SCALARS[$key]) || isset(self::SECTIONS[$key]);
    }

    /**
     * Return all valid top-level config keys.
     * @return string[]
     */
    public static function keys(): array
    {
        return array_keys(self::instance()->toArray());
    }

    /**
     * Get Config Values.
     *
     * Returns arrays rather than objects so existing callers keep working.
     *
     * @param ?string $key Config Key. Default is null for the whole config.
     * @return mixed
     */
    public static function get(?string $key = null): mixed
    {
        $config = self::instance();

        if ($key === null || $key === '') {
            return $config->toArray();
        }

        if (isset(self::SCALARS[$key])) {
            return $config->{self::SCALARS[$key]}();
        }

        return $config->section($key)?->toArray();
    }

    /**
     * The shared configuration instance backing the static API.
     * @return static
     */
    public static function instance(): static
    {
        if (!static::$instance instanceof static) {
            static::$instance = static::make();
        }

        return static::$instance;
    }

    /**
     * Reset Config back to defaults.
     * @return void
     */
    public static function reset(): void
    {
        static::$instance = null;
    }

    ######################################################################
    /*============================ KEY MAPS ============================*/
    ######################################################################

    /** @var array<string,string> Dotted key => scalar accessor. */
    private const SCALARS = [
        'trust.proxy'     => 'trustProxy',
        'trusted.proxies' => 'trustedProxies',
        'ip.version'      => 'ipVersion',
    ];

    /** @var array<string,string> Dotted key => section property. */
    private const SECTIONS = [
        'ip'             => 'ip',
        'rate.limit'     => 'rateLimit',
        'sql.injection'  => 'sqlInjection',
        'xss'            => 'xss',
        'request.filter' => 'requestFilter',
        'country'        => 'country',
    ];
}
