<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Detectors\SqlInjectionDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Detectors\SqlInjectionDetector
 */
class SqlInjectionDetectorTest extends TestCase
{
    private SqlInjectionDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new SqlInjectionDetector();
    }

    /**
     * @dataProvider maliciousPayloads
     */
    public function testDetectsMaliciousPayloads(string $payload): void
    {
        $this->assertTrue($this->detector->detect($payload), "Expected detection for: {$payload}");
    }

    /**
     * @dataProvider safeInputs
     */
    public function testAllowsSafeInputs(string $input): void
    {
        $this->assertFalse($this->detector->detect($input), "Expected no detection for: {$input}");
    }

    public static function maliciousPayloads(): array
    {
        return [
            'union select'          => ["' UNION SELECT username, password FROM users--"],
            'comment bypass'        => ["admin' --"],
            'stacked query'         => ["1; DROP TABLE users"],
            'tautology'             => ["' OR '1'='1"],
            'sleep blind'           => ["1' AND SLEEP(5)--"],
            'information schema'    => ["' AND 1=1 UNION SELECT table_name FROM information_schema.tables--"],
            'xp_cmdshell'           => ["'; EXEC xp_cmdshell('dir')--"],
            'load_file'             => ["' UNION SELECT LOAD_FILE('/etc/passwd')--"],
            'char concat'           => ["CHAR(65,66,67)"],
            'url encoded union'     => ["%27%20UNION%20SELECT%201,2,3--"],
        ];
    }

    public static function safeInputs(): array
    {
        return [
            'normal name'       => ["John Doe"],
            'normal email'      => ["user@example.com"],
            'normal search'     => ["best PHP frameworks 2024"],
            'number'            => ["42"],
            'url'               => ["https://example.com/page?id=5"],
            'sentence'          => ["I want to select the best option for my project."],
        ];
    }

    public function testHasCorrectName(): void
    {
        $this->assertSame('SQL Injection Detector', $this->detector->name());
    }
}
