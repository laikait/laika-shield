<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Rules\IpRule;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Rules\IpRule
 */
class IpRuleTest extends TestCase
{
    private function ruleWithIp(string $ip, array $blocklist = [], array $allowlist = []): IpRule
    {
        // Inject client IP via $_SERVER superglobal
        $_SERVER['REMOTE_ADDR'] = $ip;
        return new IpRule($blocklist, $allowlist, trustProxy: false);
    }

    protected function tearDown(): void
    {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testAllowsIpNotInBlocklist(): void
    {
        $rule = $this->ruleWithIp('5.5.5.5', blocklist: ['1.2.3.4']);
        $this->assertTrue($rule->passes());
    }

    public function testBlocksIpInBlocklist(): void
    {
        $rule = $this->ruleWithIp('1.2.3.4', blocklist: ['1.2.3.4']);
        $this->assertFalse($rule->passes());
        $this->assertStringContainsString('1.2.3.4', $rule->message());
    }

    public function testBlocksCidrRange(): void
    {
        $rule = $this->ruleWithIp('192.168.1.50', blocklist: ['192.168.1.0/24']);
        $this->assertFalse($rule->passes());
    }

    public function testAllowsIpInAllowlist(): void
    {
        $rule = $this->ruleWithIp('203.0.113.5', allowlist: ['203.0.113.0/24']);
        $this->assertTrue($rule->passes());
    }

    public function testBlocksIpNotInAllowlist(): void
    {
        $rule = $this->ruleWithIp('8.8.8.8', allowlist: ['203.0.113.0/24']);
        $this->assertFalse($rule->passes());
        $this->assertStringContainsString('allowlist', $rule->message());
    }

    public function testNoRulesAlwaysPasses(): void
    {
        $rule = $this->ruleWithIp('1.1.1.1');
        $this->assertTrue($rule->passes());
    }
}
