<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Contract;

/**
 * Interface DetectorInterface
 *
 * Contract for anything that inspects a value and reports a finding: threat
 * detectors (SQLi, XSS) and classifiers (GeoIP) alike.
 *
 * @package Laika\Shield\Contract
 */
interface DetectorInterface
{
    /**
     * Inspect a value and report the finding.
     *
     * Threat detectors answer true/false. Classifiers return a label, or null
     * when the value cannot be classified.
     *
     * @param  string $value           The raw value to inspect.
     * @return bool|string|null        The finding, in the implementor's terms.
     */
    public function detect(string $value): bool|string|null;

    /**
     * This detector's own label, e.g. 'xss'. NOT the finding.
     *
     * @return string
     */
    public function name(): string;
}
