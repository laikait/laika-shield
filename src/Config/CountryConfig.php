<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class CountryConfig
 *
 * Requires a MaxMind GeoLite2-Country database. Download it with geoipupdate
 * (https://github.com/maxmind/geoipupdate) using your own MaxMind licence key
 * and point db() at the result — it is not redistributed with this package.
 *
 * The country rule is skipped entirely unless db() is set AND one of the lists
 * is non-empty, because building it opens a multi-megabyte reader.
 *
 * Country codes are ISO 3166-1 alpha-2 (e.g. 'US', 'CN', 'RU').
 *
 * @package Laika\Shield\Config
 */
final class CountryConfig extends SectionConfig
{
    private string $db = '';

    /** @var string[] */
    private array $blocklist = [];

    /** @var string[] */
    private array $allowlist = [];

    /**
     * @return static|string
     */
    public function db(?string $value = null): static|string
    {
        if (func_num_args() === 0) {
            return $this->db;
        }

        $this->db = (string) $value;
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function blocklist(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blocklist;
        }

        $this->blocklist = $value ?? [];
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function allowlist(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->allowlist;
        }

        $this->allowlist = $value ?? [];
        return $this;
    }

    /**
     * Whether the country rule has enough configuration to be worth building.
     */
    public function isConfigured(): bool
    {
        return $this->db !== '' && ($this->blocklist !== [] || $this->allowlist !== []);
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'db'        => 'db',
            'blocklist' => 'blocklist',
            'allowlist' => 'allowlist',
        ];
    }
}
