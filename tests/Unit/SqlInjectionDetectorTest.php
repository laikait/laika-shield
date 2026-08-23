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

            // Every one of these was a 403 before the patterns were anchored to
            // SQL syntax instead of SQL vocabulary.
            'select from prose'  => ["Please select an item from the dropdown"],
            'the word sleep'     => ["I could not sleep last night"],
            'issue reference'    => ["See ticket #42 for details"],
            'dashes in prose'    => ["Delete this row from the sheet -- thanks"],
            'char with one arg'  => ["char(1) is a C type"],
            'apostrophe and eq'  => ["O'Brien and Sons = great"],
            'update and set'     => ["update your profile and set a new photo"],
            'path with comment'  => ["https://ex.com/a/*b*/c"],
            'drop table prose'   => ["We will drop table service after the update"],
            'insert into prose'  => ["Insert into the field the value you want"],
            'ampersand dashes'   => ["Rock & Roll -- the best genre"],
            'windows path'       => ["C:/Users/me/notes.txt"],
            'comparison prose'   => ["price > 100 and rating > 4"],
            'sleep exclamation'  => ["Sleep well!"],
        ];
    }

    /**
     * @dataProvider obfuscatedPayloads
     */
    public function testDetectsObfuscatedPayloads(string $payload): void
    {
        $this->assertTrue($this->detector->detect($payload), "Expected detection for: {$payload}");
    }

    public static function obfuscatedPayloads(): array
    {
        return [
            'mysql executable comment' => ["1' OR 1=1 /*!50000UNION*/ SELECT 1"],
            'inline comment spacing'   => ["admin'/**/OR/**/1=1#"],
            'long hex payload'         => ["0x27206f7220313d31202d2d20"],
        ];
    }

    // -------------------------------------------------------------------------
    // strict mode
    // -------------------------------------------------------------------------

    /**
     * The strict flag used to be passed to a class with no constructor, so PHP
     * discarded it silently and the option did nothing.
     */
    public function testStrictFlagIsActuallyApplied(): void
    {
        $lenient = new SqlInjectionDetector(false);
        $strict  = new SqlInjectionDetector(true);

        $this->assertFalse($lenient->detect('SELECT name FROM users'));
        $this->assertTrue($strict->detect('SELECT name FROM users'));
    }

    public function testStrictModeStillCatchesSyntaxPayloads(): void
    {
        $strict = new SqlInjectionDetector(true);

        $this->assertTrue($strict->detect("' OR '1'='1"));
    }

    public function testDefaultIsLenient(): void
    {
        $this->assertFalse((new SqlInjectionDetector())->detect('DROP TABLE accounts'));
    }

    public function testHasCorrectName(): void
    {
        $this->assertSame('SQL Injection Detector', $this->detector->name());
    }
}
