<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use Laika\Shield\Contract\DetectorInterface;

/**
 * Class SqlInjectionDetector
 *
 * Detects common SQL injection patterns in user-supplied input.
 *
 * The patterns look for SQL *syntax* — a quote next to an operator, a keyword next
 * to its parenthesis, a statement separator — rather than for SQL *words*. Matching
 * bare keywords blocks ordinary prose: "please select an item from the dropdown",
 * "I could not sleep last night" and "see ticket #42" are all legitimate input.
 *
 * @package Laika\Shield\Detectors
 */
final class SqlInjectionDetector implements DetectorInterface
{
    /**
     * Injection syntax. These require structure an attacker needs and prose does not.
     */
    private const PATTERNS = [
        // UNION-based injection: UNION ... SELECT
        '/\bunion\b[\s\S]{0,30}?\bselect\b/i',

        // Stacked queries: a statement separator followed by a new statement
        '/;\s*(select|insert|update|delete|drop|alter|create|truncate|exec|execute|grant|revoke)\b/i',

        // Comment terminator immediately after a quote or paren — the classic
        // "close the string, comment out the rest" tail. Prose containing "--"
        // or "#" without a preceding quote is left alone.
        '/[\'")]\s*(--|#|\/\*)/',

        // Tautologies: quote/paren, then a boolean operator, then a comparison.
        // Requires the leading quote so "O\'Brien and Sons = great" does not match.
        '/[\'")]\s*\b(or|and)\b\s+[\'"]?[\w.]+[\'"]?\s*(=|<>|!=|<|>|\blike\b)\s*[\'"]?[\w.]+/i',

        // Time-based blind injection — needs the call parentheses
        '/\b(sleep|benchmark|pg_sleep)\s*\(/i',
        '/\bwaitfor\s+delay\b/i',

        // File primitives
        '/\bload_file\s*\(/i',
        '/\binto\s+(outfile|dumpfile)\b/i',

        // Command execution / extended stored procedures
        '/\b(xp_|sp_)\w+/i',
        '/\b(exec|execute)\s*\(/i',

        // Schema enumeration
        '/\binformation_schema\b/i',
        '/\bsysobjects\b/i',

        // MySQL executable comments: /*! ... */ — a real bypass technique.
        // A plain /* comment */ is not, so paths like "/a/*b*/c" are left alone.
        '/\/\*!/',

        // String-construction tricks: CHAR(65,66,67) and friends. The comma is
        // what separates the attack from a benign "char(1) is a C type".
        '/\b(char|nchar|varchar|nvarchar)\s*\(\s*\d+\s*,/i',
        '/\b(group_concat|concat_ws)\s*\(/i',

        // Hex-encoded payloads of a length no ordinary field carries
        '/\b0x[0-9a-f]{16,}\b/i',
    ];

    /**
     * Keyword-only patterns. These match legitimate prose too, so they are opt-in.
     */
    private const STRICT_PATTERNS = [
        '/\bselect\b.{0,100}\bfrom\b/is',
        '/\binsert\b.{0,100}\binto\b/is',
        '/\bupdate\b.{0,100}\bset\b/is',
        '/\bdelete\b.{0,100}\bfrom\b/is',
        '/\bdrop\b.{0,20}\b(table|database|index|view|procedure|function)\b/is',
        '/\b(concat|substring|ascii|hex|unhex)\s*\(/i',
    ];

    /**
     * @param bool $strict Also apply the keyword-only patterns. Off by default:
     *                     they false-positive on ordinary sentences.
     */
    public function __construct(private readonly bool $strict = false) {}

    public function detect(string $value): bool
    {
        if ($value === '') {
            return false;
        }

        $decoded  = html_entity_decode(urldecode($value), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $patterns = $this->strict
            ? array_merge(self::PATTERNS, self::STRICT_PATTERNS)
            : self::PATTERNS;

        foreach ($patterns as $pattern) {
            $result = preg_match($pattern, $decoded);

            // preg_match() returns false on PCRE failure (backtrack limit, bad
            // UTF-8). Treating that as "clean" would let a large crafted payload
            // walk straight through the scanner, so it counts as a detection.
            if ($result === false || $result === 1) {
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
