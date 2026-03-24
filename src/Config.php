<?php

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
    private static ?self $instance = null;

    /** @var array<string,mixed> */
    protected array $config = [];

    private function __construct()
    {
        $this->config = require __DIR__ . '/Storage/config.sample.php';
    }

    // -------------------------------------------------------------------------
    // Singleton Access
    // -------------------------------------------------------------------------

    private static function getInstance(): static
    {
        if (static::$instance === null) {
            static::$instance = new static();
        }

        return static::$instance;
    }

    // -------------------------------------------------------------------------
    // API
    // -------------------------------------------------------------------------

    /**
     * Add or merge a value into the config.
     *
     * - If $subKey is provided, only that sub-key is updated.
     * - If the existing value and $value are both arrays, they are merged.
     * - Otherwise the existing value is overwritten.
     *
     * @return void
     */
    public static function add(string $key, mixed $subKeyOrValue, mixed $value = null): void
    {
        $instance = static::getInstance();

        // Two-argument call: Config::add('sql.injection', ['skip.keys' => [...]])
        // Three-argument call: Config::add('sql.injection', 'skip.keys', [...])
        if ($value !== null) {
            $subKey   = $subKeyOrValue;
            $existing = $instance->config[$key][$subKey] ?? null;

            if (is_array($existing) && is_array($value)) {
                $instance->config[$key][$subKey] = array_merge($existing, $value);
            } else {
                $instance->config[$key][$subKey] = $value;
            }

            return;
        }

        $existing = $instance->config[$key] ?? null;

        if (is_array($existing) && is_array($subKeyOrValue)) {
            $instance->config[$key] = array_merge($existing, $subKeyOrValue);
        } else {
            $instance->config[$key] = $subKeyOrValue;
        }

        return;
    }

    /**
     * Check whether a top-level key exists in the current config.
     */
    public static function has(string $key): bool
    {
        return array_key_exists($key, static::getInstance()->config);
    }

    /**
     * Return all valid top-level config keys.
     *
     * @return string[]
     */
    public static function keys(): array
    {
        return array_keys(static::getInstance()->config);
    }

    /**
     * Get Config Values
     * @param ?string $key Config Key. Default is null
     * @return mixed
     */
    public static function get(?string $key = null): mixed
    {
        $instance = static::getInstance();
        return !empty($key) ? $instance->config[$key] : $instance->config;
    }

    /**
     * Reset Config
     */
    public static function reset(): void
    {
        static::$instance = null;
    }
}
