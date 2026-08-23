<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Rules\RequestFilterRule;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Rules\RequestFilterRule
 */
class RequestFilterRuleTest extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';

        unset($_SERVER['CONTENT_LENGTH'], $_SERVER['HTTP_USER_AGENT']);
    }

    protected function tearDown(): void
    {
        unset($_SERVER['CONTENT_LENGTH'], $_SERVER['HTTP_USER_AGENT']);
    }

    // -------------------------------------------------------------------------
    // Content-Length
    // -------------------------------------------------------------------------

    /**
     * A GET carries no Content-Length. Comparing null against the minimum
     * coerced it to 0, so every such request was blocked.
     */
    public function testRequestWithoutContentLengthPassesAMinimum(): void
    {
        $rule = new RequestFilterRule(minContentLength: 10);

        $this->assertTrue($rule->passes(), 'A GET with no body must not trip the minimum.');
    }

    public function testRequestWithoutContentLengthPassesAMaximum(): void
    {
        $rule = new RequestFilterRule(maxContentLength: 10);

        $this->assertTrue($rule->passes());
    }

    public function testBodyBelowTheMinimumIsBlocked(): void
    {
        $_SERVER['CONTENT_LENGTH'] = '4';
        $rule = new RequestFilterRule(minContentLength: 10);

        $this->assertFalse($rule->passes());
        $this->assertSame(403, $rule->statusCode());
    }

    public function testBodyAboveTheMaximumIsBlockedWith413(): void
    {
        $_SERVER['CONTENT_LENGTH'] = '4096';
        $rule = new RequestFilterRule(maxContentLength: 1024);

        $this->assertFalse($rule->passes());
        $this->assertSame(413, $rule->statusCode(), 'An oversized body is 413, not 403.');
    }

    public function testBodyInsideTheBoundsPasses(): void
    {
        $_SERVER['CONTENT_LENGTH'] = '512';
        $rule = new RequestFilterRule(maxContentLength: 1024, minContentLength: 10);

        $this->assertTrue($rule->passes());
    }

    // -------------------------------------------------------------------------
    // Methods
    // -------------------------------------------------------------------------

    public function testBlockedMethodIsRejected(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'TRACE';
        $rule = new RequestFilterRule(blockedMethods: ['TRACE']);

        $this->assertFalse($rule->passes());
        $this->assertStringContainsString('TRACE', $rule->message());
    }

    public function testBlockedMethodMatchingIsCaseInsensitive(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'TRACE';
        $rule = new RequestFilterRule(blockedMethods: ['trace']);

        $this->assertFalse($rule->passes(), 'A lowercase config entry must still match.');
    }

    public function testAllowedMethodPasses(): void
    {
        $rule = new RequestFilterRule(blockedMethods: ['TRACE', 'CONNECT']);

        $this->assertTrue($rule->passes());
    }

    // -------------------------------------------------------------------------
    // URI / User-Agent / headers
    // -------------------------------------------------------------------------

    public function testBlockedUriPatternIsRejected(): void
    {
        $_SERVER['REQUEST_URI'] = '/.env';
        $rule = new RequestFilterRule(blockedUriPatterns: ['/\/\.env$/i']);

        $this->assertFalse($rule->passes());
    }

    public function testBlockedUserAgentIsRejected(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'sqlmap/1.5';
        $rule = new RequestFilterRule(blockedUserAgentPatterns: ['/sqlmap/i']);

        $this->assertFalse($rule->passes());
    }

    public function testMissingRequiredHeaderIsRejected(): void
    {
        $rule = new RequestFilterRule(requiredHeaders: ['x-api-key']);

        $this->assertFalse($rule->passes());
        $this->assertStringContainsString('x-api-key', $rule->message());
    }

    public function testPresentRequiredHeaderPasses(): void
    {
        $_SERVER['HTTP_X_API_KEY'] = 'abc123';
        $rule = new RequestFilterRule(requiredHeaders: ['x-api-key']);

        $this->assertTrue($rule->passes());

        unset($_SERVER['HTTP_X_API_KEY']);
    }

    public function testEmptyRuleSetAlwaysPasses(): void
    {
        $this->assertTrue((new RequestFilterRule())->passes());
    }
}
