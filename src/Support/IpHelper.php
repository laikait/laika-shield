<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Support;

/**
 * Class IpHelper
 *
 * Utility methods for IP address detection, validation, and version detection.
 *
 * @package Laika\Shield\Support
 */
final class IpHelper
{
    // -------------------------------------------------------------------------
    // IP Version Detection
    // -------------------------------------------------------------------------

    /**
     * Detect whether an IP is v4 or v6.
     *
     * @return 4|6|null  Returns 4 for IPv4, 6 for IPv6, null if invalid.
     */
    public static function version(string $ip): int|null
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 4;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 6;
        }

        return null;
    }

    /**
     * Check whether the IP is a valid IPv4 address.
     */
    public static function isV4(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    /**
     * Check whether the IP is a valid IPv6 address.
     */
    public static function isV6(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

    /**
     * Check whether the IP is valid (either v4 or v6).
     */
    public static function isValid(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP);
    }

    // -------------------------------------------------------------------------
    // CIDR / Range Matching
    // -------------------------------------------------------------------------

    /**
     * Check whether an IP falls inside a CIDR range (e.g. 192.168.0.0/24).
     * Supports both IPv4 and IPv6 CIDR notation.
     */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $prefix] = explode('/', $cidr, 2);
        $prefix = (int) $prefix;

        if (self::isV4($ip) && self::isV4($subnet)) {
            return self::inCidrV4($ip, $subnet, $prefix);
        }

        if (self::isV6($ip) && self::isV6($subnet)) {
            return self::inCidrV6($ip, $subnet, $prefix);
        }

        return false;
    }

    /**
     * Check whether the IP is inside any of the given CIDR ranges.
     *
     * @param string[] $cidrs
     */
    public static function inAnyCidr(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::inCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Special-purpose IP checks
    // -------------------------------------------------------------------------

    /**
     * Returns true if the IP is a loopback address (127.x.x.x or ::1).
     */
    public static function isLoopback(string $ip): bool
    {
        return self::inCidr($ip, '127.0.0.0/8') || $ip === '::1';
    }

    /**
     * Returns true if the IP is a private/RFC-1918 or private IPv6 address.
     */
    public static function isPrivate(string $ip): bool
    {
        if (self::isV4($ip)) {
            return self::inAnyCidr($ip, [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '127.0.0.0/8',
            ]);
        }

        if (self::isV6($ip)) {
            // fc00::/7 — Unique Local Addresses
            return self::inCidr($ip, 'fc00::/7') || $ip === '::1';
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Client IP resolution
    // -------------------------------------------------------------------------

    /**
     * Resolve the real client IP from superglobals, respecting common
     * proxy / load-balancer headers when $trustProxy is true.
     */
    public static function resolve(bool $trustProxy = false): string
    {
        if ($trustProxy) {
            $headers = [
                'HTTP_CF_CONNECTING_IP',   // Cloudflare
                'HTTP_X_REAL_IP',          // Nginx proxy
                'HTTP_X_FORWARDED_FOR',    // Standard proxy header
                'HTTP_X_FORWARDED',
                'HTTP_FORWARDED_FOR',
                'HTTP_FORWARDED',
                'HTTP_CLIENT_IP',
            ];

            foreach ($headers as $header) {
                $value = $_SERVER[$header] ?? '';
                if ($value === '') {
                    continue;
                }

                // X-Forwarded-For may contain a comma-separated list
                $ip = trim(explode(',', $value)[0]);

                if (self::isValid($ip)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static function inCidrV4(string $ip, string $subnet, int $prefix): bool
    {
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask       = $prefix === 0 ? 0 : (~0 << (32 - $prefix));

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private static function inCidrV6(string $ip, string $subnet, int $prefix): bool
    {
        $ipBin     = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $bits   = 128;
        $ipArr  = unpack('C*', $ipBin);
        $subArr = unpack('C*', $subnetBin);

        $bytesFull = (int) ($prefix / 8);
        $bitsLeft  = $prefix % 8;

        // Compare full bytes
        for ($i = 1; $i <= $bytesFull; $i++) {
            if ($ipArr[$i] !== $subArr[$i]) {
                return false;
            }
        }

        // Compare remaining partial byte
        if ($bitsLeft > 0 && $bytesFull < 16) {
            $mask = 0xFF & (0xFF << (8 - $bitsLeft));
            if (($ipArr[$bytesFull + 1] & $mask) !== ($subArr[$bytesFull + 1] & $mask)) {
                return false;
            }
        }

        return true;
    }
}
