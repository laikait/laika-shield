<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use MaxMind\Db\Reader\InvalidDatabaseException;

/**
 * Class GeoIpDetector
 *
 * Resolves a country ISO code from an IP address using a local
 * MaxMind GeoLite2-Country (.mmdb) database file.
 *
 * @package Laika\Shield\Detectors
 */
final class GeoIpDetector
{
    private Reader $reader;

    /**
     * @param string $dbPath  Absolute path to the GeoLite2-Country.mmdb file.
     * @throws InvalidDatabaseException
     */
    public function __construct(string $dbPath)
    {
        $this->reader = new Reader($dbPath);
    }

    /**
     * Resolve the ISO 3166-1 alpha-2 country code for the given IP.
     * Returns null if the IP is private, loopback, or not found in the DB.
     *
     * @param  string $ip
     * @return string|null  e.g. 'US', 'CN', 'RU'
     */
    public function detect(string $ip): ?string
    {
        try {
            $record = $this->reader->country($ip);
            return $record->country->isoCode;
        } catch (AddressNotFoundException) {
            return null;
        }
    }

    public function __destruct()
    {
        $this->reader->close();
    }
}
