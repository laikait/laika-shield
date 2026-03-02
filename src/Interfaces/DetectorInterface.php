<?php

declare(strict_types=1);

namespace Laika\Shield\Interfaces;

/**
 * Interface DetectorInterface
 *
 * Contract for pattern-based threat detectors (e.g. SQLi, XSS).
 *
 * @package Laika\Shield\Interfaces
 */
interface DetectorInterface
{
    /**
     * Scan the given value for threats.
     *
     * @param  string $value  The raw input value to inspect.
     * @return bool           True if a threat is detected, false otherwise.
     */
    public function detect(string $value): bool;

    /**
     * Return the name/label of this detector.
     */
    public function name(): string;
}
