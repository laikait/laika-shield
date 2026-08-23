<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Support\IpHelper;
use PHPUnit\Framework\TestCase;

/**
 * Client-IP resolution and CIDR-range hardening.
 *
 * @covers \Laika\Shield\Support\IpHelper
 */
class IpHelperResolveTest extends TestCase
{
    protected function setUp(): void
    {
        foreach (array_keys($_SERVER) as $key) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                unset($_SERVER[$key]);
            }
        }

        $_SERVER['REMOTE_ADDR'] = '198.51.100.7';
    }

    protected function tearDown(): void
    {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    // -------------------------------------------------------------------------
    // Spoofing
    // -------------------------------------------------------------------------

    public function testForwardedHeadersAreIgnoredWhenProxyIsNotTrusted(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR']  = '8.8.8.8';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '8.8.8.8';

        $this->assertSame('198.51.100.7', IpHelper::resolve(false));
    }

    /**
     * The old code took the LEFTMOST X-Forwarded-For entry — the one value a
     * client fully controls — so any IP ban was one header away from bypass.
     */
    public function testClientSuppliedLeftmostForwardedEntryIsNotTrusted(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.8.8, 203.0.113.5';

        $resolved = IpHelper::resolve(true, ['198.51.100.0/24']);

        $this->assertNotSame('8.8.8.8', $resolved, 'The forged leftmost hop must never win.');
        $this->assertSame('203.0.113.5', $resolved);
    }

    public function testSingleValueHeadersAreIgnoredWithoutATrustedProxyList(): void
    {
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '8.8.8.8';

        // A direct client can send CF-Connecting-IP just as easily as Cloudflare.
        $this->assertSame('198.51.100.7', IpHelper::resolve(true));
    }

    public function testSingleValueHeaderIsHonouredFromATrustedPeer(): void
    {
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.5';

        $this->assertSame('203.0.113.5', IpHelper::resolve(true, ['198.51.100.0/24']));
    }

    public function testTrustedHopsAreWalkedFromTheRight(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5, 10.0.0.8, 10.0.0.9';

        $this->assertSame(
            '203.0.113.5',
            IpHelper::resolve(true, ['198.51.100.0/24', '10.0.0.0/8'])
        );
    }

    public function testFallsBackToRemoteAddrWhenEveryHopIsTrusted(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.8, 10.0.0.9';

        $this->assertSame('198.51.100.7', IpHelper::resolve(true, ['198.51.100.0/24', '10.0.0.0/8']));
    }

    public function testRightmostEntryWinsWithoutATrustedList(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.8.8, 203.0.113.5';

        $this->assertSame('203.0.113.5', IpHelper::resolve(true));
    }

    public function testPortIsStrippedFromForwardedEntries(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5:51234';

        $this->assertSame('203.0.113.5', IpHelper::resolve(true));
    }

    public function testBracketedIpv6IsUnwrapped(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '[2001:db8::1]:443';

        $this->assertSame('2001:db8::1', IpHelper::resolve(true));
    }

    public function testGarbageForwardedHeaderFallsBackToRemoteAddr(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip';

        $this->assertSame('198.51.100.7', IpHelper::resolve(true));
    }

    // -------------------------------------------------------------------------
    // CIDR ranges
    // -------------------------------------------------------------------------

    /**
     * An out-of-range prefix reached a negative bit shift, which is a fatal
     * ArithmeticError in PHP 8 — one typo in a blocklist 500'd every request.
     */
    public function testOutOfRangeIpv4PrefixReturnsFalseInsteadOfThrowing(): void
    {
        $this->assertFalse(IpHelper::inCidr('1.2.3.4', '1.2.3.4/33'));
        $this->assertFalse(IpHelper::inCidr('1.2.3.4', '1.2.3.4/999'));
    }

    public function testOutOfRangeIpv6PrefixReturnsFalse(): void
    {
        $this->assertFalse(IpHelper::inCidr('2001:db8::1', '2001:db8::/129'));
        $this->assertFalse(IpHelper::inCidr('2001:db8::1', '2001:db8::/200'));
    }

    public function testMalformedPrefixReturnsFalse(): void
    {
        $this->assertFalse(IpHelper::inCidr('1.2.3.4', '1.2.3.4/'));
        $this->assertFalse(IpHelper::inCidr('1.2.3.4', '1.2.3.4/abc'));
        $this->assertFalse(IpHelper::inCidr('1.2.3.4', '1.2.3.4/-1'));
    }

    public function testBoundaryPrefixesStillWork(): void
    {
        $this->assertTrue(IpHelper::inCidr('1.2.3.4', '1.2.3.4/32'));
        $this->assertTrue(IpHelper::inCidr('1.2.3.4', '0.0.0.0/0'));
        $this->assertTrue(IpHelper::inCidr('2001:db8::1', '2001:db8::1/128'));
    }

    public function testBlocklistWithABadEntryStillEvaluatesTheRest(): void
    {
        $this->assertTrue(IpHelper::inAnyCidr('10.0.0.5', ['1.2.3.4/33', '10.0.0.0/8']));
    }
}
