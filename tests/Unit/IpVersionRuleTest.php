<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Rules\IpVersionRule;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Rules\IpVersionRule
 */
class IpVersionRuleTest extends TestCase
{
    protected function tearDown(): void
    {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testAllowsIpv4WhenAllowedVersionIs4(): void
    {
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        $rule = new IpVersionRule(4);
        $this->assertTrue($rule->passes());
    }

    public function testBlocksIpv6WhenAllowedVersionIs4(): void
    {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::1';
        $rule = new IpVersionRule(4);
        $this->assertFalse($rule->passes());
        $this->assertStringContainsString('IPv6', $rule->message());
    }

    public function testAllowsIpv6WhenAllowedVersionIs6(): void
    {
        $_SERVER['REMOTE_ADDR'] = '::1';
        $rule = new IpVersionRule(6);
        $this->assertTrue($rule->passes());
    }

    public function testBlocksIpv4WhenAllowedVersionIs6(): void
    {
        $_SERVER['REMOTE_ADDR'] = '1.2.3.4';
        $rule = new IpVersionRule(6);
        $this->assertFalse($rule->passes());
    }

    public function testNullVersionAllowsBoth(): void
    {
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        $this->assertTrue((new IpVersionRule(null))->passes());

        $_SERVER['REMOTE_ADDR'] = '::1';
        $this->assertTrue((new IpVersionRule(null))->passes());
    }

    public function testDetectedVersionReturnsCorrectValue(): void
    {
        $_SERVER['REMOTE_ADDR'] = '1.1.1.1';
        $rule = new IpVersionRule(4);
        $this->assertSame(4, $rule->detectedVersion());
    }
}
