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
    private int $statusCode = 200;

    /**
     * @param string[] $skipKeys  Input keys to skip (e.g. ['password', 'token']).
     * @param bool     $scanBody  Whether to also scan the raw request body.
     * @param bool     $strict    When true, also blocks standalone DML keywords
     *                            (SELECT/INSERT/UPDATE/DELETE/DROP).
     */
    public function __construct(
        private readonly array $skipKeys = [],
        private readonly bool $scanBody = true,
        private readonly bool $strict = true,
    ) {}

    public function passes(): bool
    {
        $detector = new SqlInjectionDetector($this->strict);
        $inputs   = $this->scanBody
            ? RequestHelper::allInput()
            : array_merge(RequestHelper::queryParams(), RequestHelper::bodyParams());

        foreach ($inputs as $key => $value) {
            if (in_array($key, $this->skipKeys, true)) {
                continue;
            }

            if ($detector->detect($value)) {
                $this->blockMessage = "SQL Injection Detected In Input Key: [{$key}].";
                $this->statusCode = 403;
                return false;
            }
        }

        return true;
    }

    /**
     * Return Response Code
     * @return int
     */
    public function statusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Set Addetional Header if Required. Example: header('Refresh: 0');
     * @return void
     */
    public function additionalHeader(): void
    {
        return;
    }

    /**
     * Return Messsage
     * @return string
     */
    public function message(): string
    {
        return $this->blockMessage;
    }
}
