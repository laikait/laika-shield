<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Detectors\XssDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Detectors\XssDetector
 */
class XssDetectorTest extends TestCase
{
    private XssDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new XssDetector();
    }

    /**
     * @dataProvider maliciousPayloads
     */
    public function testDetectsMaliciousPayloads(string $payload): void
    {
        $this->assertTrue($this->detector->detect($payload), "Expected XSS detection for: {$payload}");
    }

    /**
     * @dataProvider safeInputs
     */
    public function testAllowsSafeInputs(string $input): void
    {
        $this->assertFalse($this->detector->detect($input), "Expected no XSS detection for: {$input}");
    }

    public static function maliciousPayloads(): array
    {
        return [
            'script tag'            => ['<script>alert(1)</script>'],
            'onclick handler'       => ['<img onclick="alert(1)" src="x">'],
            'javascript protocol'   => ['<a href="javascript:alert(1)">click</a>'],
            'onerror handler'       => ['<img src=x onerror=alert(1)>'],
            'eval call'             => ['eval("alert(1)")'],
            'iframe injection'      => ['<iframe src="http://evil.com"></iframe>'],
            'svg xss'               => ['<svg onload="alert(1)">'],
            'encoded script'        => ['%3Cscript%3Ealert(1)%3C/script%3E'],
            'vbscript protocol'     => ['<a href="vbscript:msgbox(1)">x</a>'],
            'expression css'        => ['background:expression(alert(1))'],
        ];
    }

    public static function safeInputs(): array
    {
        return [
            'plain text'        => ['Hello, World!'],
            'normal html desc'  => ['This is a paragraph about <strong>bold text</strong>.'],
            'email'             => ['user@example.com'],
            'url safe'          => ['https://example.com/search?q=hello+world'],
            'number string'     => ['123456'],
        ];
    }

    public function testHasCorrectName(): void
    {
        $this->assertSame('XSS Detector', $this->detector->name());
    }
}
