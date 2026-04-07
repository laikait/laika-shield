<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Interfaces;

/**
 * Interface RuleInterface
 *
 * Every firewall rule must implement this contract.
 *
 * @package Laika\Shield\Interfaces
 */
interface RuleInterface
{
    /**
     * Evaluate the rule against the current request.
     * @return bool True if the request passes (is allowed), false if it should be blocked.
     */
    public function passes(): bool;

    /**
     * Return Error Message.
     * @return string
     */
    public function message(): string;

    /**
     * Return Response Code.
     * @return int
     */
    public function statusCode(): int;

    /**
     * Set Addetional Header if Required. Example: header('Refresh: 0');
     * @return void
     */
    public function additionalHeader(): void;
}
