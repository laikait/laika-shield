<?php

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Detectors\SqlInjectionDetector;
use Laika\Shield\Support\RequestHelper;

/**
 * Class SqlInjectionRule
 *
 * Scans query parameters, POST body, and raw input for SQL injection patterns.
 *
 * @package Laika\Shield\Rules
 */
final class SqlInjectionRule implements RuleInterface
{
    private string $blockMessage = '';

    /**
     * @param string[] $skipKeys  Input keys to skip (e.g. ['password', 'token']).
     * @param bool     $scanBody  Whether to also scan the raw request body.
     */
    public function __construct(
        private readonly array $skipKeys = [],
        private readonly bool $scanBody = true,
    ) {}

    public function passes(): bool
    {
        $detector = new SqlInjectionDetector();
        $inputs   = $this->scanBody
            ? RequestHelper::allInput()
            : array_merge(RequestHelper::queryParams(), RequestHelper::bodyParams());

        foreach ($inputs as $key => $value) {
            if (in_array($key, $this->skipKeys, true)) {
                continue;
            }

            if ($detector->detect($value)) {
                $this->blockMessage = "SQL injection detected in input key: \"{$key}\".";
                return false;
            }
        }

        return true;
    }

    public function message(): string
    {
        return $this->blockMessage;
    }
}
