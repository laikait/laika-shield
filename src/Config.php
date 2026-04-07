<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield;

/**
 * Class Config
 *
 * Loads the default Shield configuration and provides a simple API
 * to read, extend, and validate it.
 *
 * Usage:
 *
 *   // Load defaults
 *   $config = Config::getInstance();
 *
 *   // Override a scalar value
 *   Config::add('trust.proxy', true);
 *
 *   // Merge into an array value
 *   Config::add('ip', ['blocklist' => ['1.2.3.4']]);
 *
 *   // Check key existence
 *   Config::has('rate.limit'); // true
 *
 *   // Get all valid top-level keys
 *   Config::keys();
 *
 *   // Pass to Shield
 *   Shield::boot($config->all());
 *
 * @package Laika\Shield
 */
class Config
{
    private static ?Config $instance = null;

    /** @var array<string,mixed> */
    protected array $config = [];

    ######################################################################
    /*========================== EXTERNAL API ==========================*/
    ######################################################################

    /**
     * Add or merge a value into the config.
     * @param string $add Config Key
     * @param mixed $subKeyOrValue Sub Key Or Value
     * @param mixed $value Default is Null
     * @return void
     */
    public static function add(string $key, mixed $subKeyOrValue, mixed $value = null): void
    {
        self::init();

        // Two-argument call: Config::add('sql.injection', ['skip.keys' => [...]])
        // Three-argument call: Config::add('sql.injection', 'skip.keys', [...])
        if ($value !== null) {
            $subKey   = $subKeyOrValue;
            $existing = $instance->config[$key][$subKey] ?? null;

            if (is_array($existing) && is_array($value)) {
                self::$instance->config[$key][$subKey] = array_merge($existing, $value);
            } else {
                self::$instance->config[$key][$subKey] = $value;
            }

            return;
        }

        $existing = $instance->config[$key] ?? null;

        if (is_array($existing) && is_array($subKeyOrValue)) {
            self::$instance->config[$key] = array_merge($existing, $subKeyOrValue);
        } else {
            self::$instance->config[$key] = $subKeyOrValue;
        }

        return;
    }

    /**
     * Check whether a top-level key exists in the current config.
     * @return bool
     */
    public static function has(string $key): bool
    {
        self::init();
        return array_key_exists($key, self::$instance->config);
    }

    /**
     * Return all valid top-level config keys.
     * @return string[]
     */
    public static function keys(): array
    {
        self::init();
        return array_keys(self::$instance->config);
    }

    /**
     * Get Config Values
     * @param ?string $key Config Key. Default is null
     * @return mixed
     */
    public static function get(?string $key = null): mixed
    {
        self::init();
        return !empty($key) ? self::$instance->config[$key] : self::$instance->config;
    }

    /**
     * Reset Config
     * @return void
     */
    public static function reset(): void
    {
        static::$instance = null;
    }

    ######################################################################
    /*========================== INTERNAL API ==========================*/
    ######################################################################

    /**
     * Initiate Instance
     * @return static
     */
    private static function init(): void
    {
        if (static::$instance === null) {
            static::$instance = new static();
            static::$instance->config = require __DIR__ . '/Storage/config.sample.php';
        }
    }
}
