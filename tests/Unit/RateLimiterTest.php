<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Support\RateLimiter;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Support\RateLimiter
 */
class RateLimiterTest extends TestCase
{
    private RateLimiter $limiter;
    private string $storageDir;

    protected function setUp(): void
    {
        $this->storageDir = sys_get_temp_dir() . '/laika_shield_rl_test_' . uniqid();
        $this->limiter    = new RateLimiter($this->storageDir);
    }

    protected function tearDown(): void
    {
        // Cleanup temp files
        if (is_dir($this->storageDir)) {
            array_map('print', glob($this->storageDir . '/*.json') ?: []);
            rmdir($this->storageDir);
        }
    }

    public function testAllowsHitsWithinLimit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $exceeded = $this->limiter->tooMany('test_key', 5, 60);
        }

        $this->assertFalse($exceeded);
    }

    public function testBlocksAfterExceedingLimit(): void
    {
        for ($i = 0; $i < 6; $i++) {
            $exceeded = $this->limiter->tooMany('test_key2', 5, 60);
        }

        $this->assertTrue($exceeded);
    }

    public function testResetsCounter(): void
    {
        for ($i = 0; $i < 6; $i++) {
            $this->limiter->tooMany('test_key3', 5, 60);
        }

        $this->limiter->reset('test_key3');

        $exceeded = $this->limiter->tooMany('test_key3', 5, 60);
        $this->assertFalse($exceeded);
    }

    public function testRetryAfterIsPositiveWhenLimitExceeded(): void
    {
        for ($i = 0; $i < 6; $i++) {
            $this->limiter->tooMany('test_key4', 5, 60);
        }

        $retryAfter = $this->limiter->retryAfter('test_key4');
        $this->assertGreaterThan(0, $retryAfter);
        $this->assertLessThanOrEqual(60, $retryAfter);
    }
}
