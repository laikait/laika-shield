<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Support\IpHelper;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Support\IpHelper
 */
class IpHelperTest extends TestCase
{
    // -------------------------------------------------------------------------
    // version()
    // -------------------------------------------------------------------------

    public function testDetectsIpv4(): void
    {
        $this->assertSame(4, IpHelper::version('192.168.1.1'));
        $this->assertSame(4, IpHelper::version('8.8.8.8'));
        $this->assertSame(4, IpHelper::version('127.0.0.1'));
    }

    public function testDetectsIpv6(): void
    {
        $this->assertSame(6, IpHelper::version('::1'));
        $this->assertSame(6, IpHelper::version('2001:db8::1'));
        $this->assertSame(6, IpHelper::version('fe80::1'));
    }

    public function testReturnsNullForInvalidIp(): void
    {
        $this->assertNull(IpHelper::version('not-an-ip'));
        $this->assertNull(IpHelper::version(''));
        $this->assertNull(IpHelper::version('999.999.999.999'));
    }

    // -------------------------------------------------------------------------
    // isV4() / isV6()
    // -------------------------------------------------------------------------

    public function testIsV4(): void
    {
        $this->assertTrue(IpHelper::isV4('10.0.0.1'));
        $this->assertFalse(IpHelper::isV4('::1'));
        $this->assertFalse(IpHelper::isV4('invalid'));
    }

    public function testIsV6(): void
    {
        $this->assertTrue(IpHelper::isV6('::1'));
        $this->assertTrue(IpHelper::isV6('2001:db8::1'));
        $this->assertFalse(IpHelper::isV6('192.168.0.1'));
    }

    // -------------------------------------------------------------------------
    // inCidr()
    // -------------------------------------------------------------------------

    public function testInCidrIpv4(): void
    {
        $this->assertTrue(IpHelper::inCidr('192.168.1.50', '192.168.1.0/24'));
        $this->assertFalse(IpHelper::inCidr('192.168.2.1', '192.168.1.0/24'));
        $this->assertTrue(IpHelper::inCidr('10.0.0.1', '10.0.0.0/8'));
        $this->assertFalse(IpHelper::inCidr('11.0.0.1', '10.0.0.0/8'));
    }

    public function testInCidrExactMatch(): void
    {
        $this->assertTrue(IpHelper::inCidr('1.2.3.4', '1.2.3.4'));
        $this->assertFalse(IpHelper::inCidr('1.2.3.5', '1.2.3.4'));
    }

    public function testInCidrIpv6(): void
    {
        $this->assertTrue(IpHelper::inCidr('2001:db8::1', '2001:db8::/32'));
        $this->assertFalse(IpHelper::inCidr('2001:db9::1', '2001:db8::/32'));
    }

    // -------------------------------------------------------------------------
    // isPrivate() / isLoopback()
    // -------------------------------------------------------------------------

    public function testIsPrivate(): void
    {
        $this->assertTrue(IpHelper::isPrivate('192.168.0.1'));
        $this->assertTrue(IpHelper::isPrivate('10.0.0.1'));
        $this->assertTrue(IpHelper::isPrivate('172.16.0.1'));
        $this->assertFalse(IpHelper::isPrivate('8.8.8.8'));
    }

    public function testIsLoopback(): void
    {
        $this->assertTrue(IpHelper::isLoopback('127.0.0.1'));
        $this->assertTrue(IpHelper::isLoopback('::1'));
        $this->assertFalse(IpHelper::isLoopback('192.168.0.1'));
    }
}
