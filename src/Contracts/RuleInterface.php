<?php

declare(strict_types=1);

namespace Laika\Shield\Contracts;

/**
 * Interface RuleInterface
 *
 * Every firewall rule must implement this contract.
 *
 * @package Laika\Shield\Contracts
 */
interface RuleInterface
{
    /**
     * Evaluate the rule against the current request.
     *
     * @return bool True if the request passes (is allowed), false if it should be blocked.
     */
    public function passes(): bool;

    /**
     * Return the human-readable reason this rule blocked the request.
     */
    public function message(): string;
}
