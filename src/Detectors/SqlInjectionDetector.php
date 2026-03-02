<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use Laika\Shield\Interfaces\DetectorInterface;

/**
 * Class SqlInjectionDetector
 *
 * Detects common SQL injection patterns in user-supplied input.
 *
 * @package Laika\Shield\Detectors
 */
final class SqlInjectionDetector implements DetectorInterface
{
    /**
     * Regex patterns that commonly appear in SQL injection attempts.
     * Each entry is a named pattern group for easier debugging.
     */
    private const PATTERNS = [
        // UNION-based injection
        '/(\bunion\b.{0,20}\bselect\b)/i',
        // Comment-based injection: -- or #
        '/(-{2,}|#)\s*(\w|\s)*$/',
        // Stacked queries / multiple statements
        '/;\s*(select|insert|update|delete|drop|alter|create|truncate|exec|execute)/i',
        // Classic always-true tautologies
        '/\b(or|and)\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?/i',
        // Batched exec / xp_cmdshell
        '/\bexec(\s|\()/i',
        '/\bxp_cmdshell\b/i',
        // Information schema leakage
        '/\binformation_schema\b/i',
        // Inline comment bypass: /*!...*/ 
        '/\/\*.*?\*\//s',
        // Sleep / benchmark (time-based blind)
        '/\b(sleep|benchmark|waitfor\s+delay)\b/i',
        // LOAD_FILE / INTO OUTFILE
        '/\b(load_file|into\s+outfile|into\s+dumpfile)\b/i',
        // hex / char / concat tricks
        '/\b(char|nchar|varchar|concat|group_concat)\s*\(/i',
    ];

    public function detect(string $value): bool
    {
        $decoded = html_entity_decode(urldecode($value));

        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $decoded)) {
                return true;
            }
        }

        return false;
    }

    public function name(): string
    {
        return 'SQL Injection Detector';
    }
}
