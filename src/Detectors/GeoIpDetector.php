<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use MaxMind\Db\Reader\InvalidDatabaseException;
use InvalidArgumentException;
use Laika\Shield\Contract\DetectorInterface;

/**
 * Class GeoIpDetector
 *
 * Resolves a country ISO code from an IP address using a local
 * MaxMind GeoLite2-Country (.mmdb) database file.
 *
 * @package Laika\Shield\Detectors
 */
final class GeoIpDetector implements DetectorInterface
{
    private ?Reader $reader = null;

    /**
     * One lookup per IP, so detect() and countryName() for the same address
     * cost exactly one database read between them.
     *
     * @var array<string, array{iso: ?string, name: ?string}>
     */
    private array $records = [];

    /**
     * @param string $dbPath  Absolute path to the GeoLite2-Country.mmdb file.
     */
    public function __construct(private readonly string $dbPath)
    {
    }

    /**
     * Resolve the ISO 3166-1 alpha-2 country code for the given IP.
     * Returns null if the IP is private, loopback, not found, or the database
     * is unavailable.
     *
     * @param  string $value  The IP address to classify.
     * @return string|null    e.g. 'US', 'CN', 'RU'
     */
    public function detect(string $value): ?string
    {
        return $this->lookup($value)['iso'];
    }

    /**
     * Resolve the human-readable country name for the given IP.
     *
     * @param  string $ip  The IP address to classify.
     * @return string|null e.g. 'United States'
     */
    public function countryName(string $ip): ?string
    {
        return $this->lookup($ip)['name'];
    }

    /**
     * This detector's label. The country it resolves is returned by detect()
     * and countryName(), not by this.
     *
     * @return string
     */
    public function name(): string
    {
        return 'geoip';
    }

    /**
     * @param  string $ip
     * @return array{iso: ?string, name: ?string}
     */
    private function lookup(string $ip): array
    {
        if (isset($this->records[$ip])) {
            return $this->records[$ip];
        }

        $this->records[$ip] = ['iso' => null, 'name' => null];

        $reader = $this->reader();

        if ($reader === null) {
            return $this->records[$ip];
        }

        try {
            $country = $reader->country($ip)->country;

            $this->records[$ip] = [
                'iso'  => $country->isoCode,
                'name' => $country->name,
            ];
        } catch (AddressNotFoundException | InvalidDatabaseException | InvalidArgumentException) {
            // Private/loopback/unknown address, or an unreadable database.
        }

        return $this->records[$ip];
    }

    private function reader(): ?Reader
    {
        if ($this->reader instanceof Reader) {
            return $this->reader;
        }

        if (!is_file($this->dbPath) || !is_readable($this->dbPath)) {
            return null;
        }

        try {
            $this->reader = new Reader($this->dbPath);
        } catch (InvalidDatabaseException) {
            return null;
        }

        return $this->reader;
    }

    public function __destruct()
    {
        $this->reader?->close();
    }
}
