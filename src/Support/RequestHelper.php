<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Support;

/**
 * Class RequestHelper
 *
 * Convenient wrappers around PHP superglobals for request data extraction.
 *
 * @package Laika\Shield\Support
 */
final class RequestHelper
{
    /**
     * Return all query-string parameters as a flat key=>value array.
     *
     * @return array<string, string>
     */
    public static function queryParams(): array
    {
        return self::flatten($_GET);
    }

    /**
     * Return all POST body parameters as a flat key=>value array.
     *
     * @return array<string, string>
     */
    public static function bodyParams(): array
    {
        return self::flatten($_POST);
    }

    /**
     * Return raw PHP input body (e.g. JSON, XML).
     */
    public static function rawBody(): string
    {
        return (string) file_get_contents('php://input');
    }

    /**
     * Return all request headers in lowercase-key format.
     *
     * @return array<string, string>
     */
    public static function headers(): array
    {
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name           = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = (string) $value;
            }
        }

        // Also pick up CONTENT_TYPE and CONTENT_LENGTH
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['content-length'] = $_SERVER['CONTENT_LENGTH'];
        }

        return $headers;
    }

    /**
     * Return the HTTP request method (GET, POST, PUT …).
     */
    public static function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    /**
     * Return the raw URI (path + query string).
     */
    public static function uri(): string
    {
        return $_SERVER['REQUEST_URI'] ?? '/';
    }

    /**
     * Collect ALL user-supplied input from query, body, and raw body into one array.
     *
     * @return array<string, string>
     */
    public static function allInput(): array
    {
        $inputs = array_merge(
            self::queryParams(),
            self::bodyParams(),
        );

        // Try to parse raw body as JSON.
        // Skip raw body entirely for multipart/form-data — PHP already parses
        // those fields into $_POST/$_GET, and the raw multipart boundary string
        // would produce false-positive injection detections.
        $contentType = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
        $isMultipart = str_contains($contentType, 'multipart/form-data');

        $raw = self::rawBody();
        if (!$isMultipart && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $inputs = array_merge($inputs, self::flatten($decoded));
            } else {
                // Treat raw body as a single string value (e.g. XML, plain text)
                $inputs['__raw_body__'] = $raw;
            }
        }

        return $inputs;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Recursively flatten a nested array into a flat key=>string array.
     *
     * @param  array<mixed,mixed> $data
     * @return array<string,string>
     */
    private static function flatten(array $data, string $prefix = ''): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            $fullKey = $prefix !== '' ? "{$prefix}[{$key}]" : (string) $key;

            if (is_array($value)) {
                $result = array_merge($result, self::flatten($value, $fullKey));
            } else {
                $result[$fullKey] = (string) $value;
            }
        }

        return $result;
    }
}
