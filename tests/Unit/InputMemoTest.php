<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Config;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Shield;
use Laika\Shield\Support\RequestHelper;
use PHPUnit\Framework\TestCase;

/**
 * RequestHelper::allInput() memoises into a static, so the memo must not survive
 * from one firewall run to the next. Under a long-running worker (RoadRunner,
 * Swoole, FrankenPHP) a stale memo means a request is judged against the PREVIOUS
 * request's body.
 *
 * @covers \Laika\Shield\Support\RequestHelper
 * @covers \Laika\Shield\Shield
 */
class InputMemoTest extends TestCase
{
    protected function setUp(): void
    {
        Config::reset();
        RequestHelper::flush();

        $_SERVER['REMOTE_ADDR']    = '203.0.113.44';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';
        $_GET                      = [];
        $_POST                     = [];
    }

    protected function tearDown(): void
    {
        Config::reset();
        RequestHelper::flush();

        $_GET  = [];
        $_POST = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testAllInputIsMemoisedWithinOneRun(): void
    {
        $_GET = ['q' => 'first'];
        $this->assertSame('first', RequestHelper::allInput()['q']);

        // Same run: the memo is intentionally reused, so a second read is stable
        // even though the superglobal moved underneath it.
        $_GET = ['q' => 'second'];
        $this->assertSame('first', RequestHelper::allInput()['q']);
    }

    public function testFlushDropsTheMemo(): void
    {
        $_GET = ['q' => 'first'];
        RequestHelper::allInput();

        $_GET = ['q' => 'second'];
        RequestHelper::flush();

        $this->assertSame('second', RequestHelper::allInput()['q']);
    }

    /**
     * The regression: a clean request following a malicious one must not inherit
     * the attack payload, and must not be blocked because of it.
     */
    public function testCleanRequestAfterAMaliciousOneIsNotBlocked(): void
    {
        $storage = sys_get_temp_dir() . '/laika_memo_' . uniqid();
        Config::rateLimit()->storageDir($storage)->maxHits(1000);

        // Request 1 — carries an XSS payload and is blocked.
        $_GET = ['bio' => '<script>alert(1)</script>'];

        $blocked = false;
        try {
            Shield::boot();
        } catch (FirewallException) {
            $blocked = true;
        }

        $this->assertTrue($blocked, 'The malicious request must be blocked.');

        // Request 2 — same process, clean input. Without the flush in inspect(),
        // the memo still holds request 1's payload and this is blocked too.
        $_GET = ['bio' => 'perfectly ordinary text'];

        Shield::boot();

        $this->assertSame(
            'perfectly ordinary text',
            RequestHelper::allInput()['bio'],
            'The second run must scan its own input, not the previous one.'
        );

        foreach (glob($storage . '/*') ?: [] as $f) {
            @unlink($f);
        }

        @rmdir($storage);
    }

    /**
     * And the reverse: a malicious request following a clean one must still be
     * caught, rather than being waved through on a stale clean memo.
     */
    public function testMaliciousRequestAfterACleanOneIsStillBlocked(): void
    {
        $storage = sys_get_temp_dir() . '/laika_memo_' . uniqid();
        Config::rateLimit()->storageDir($storage)->maxHits(1000);

        $_GET = ['bio' => 'perfectly ordinary text'];
        Shield::boot();

        $_GET = ['bio' => '<script>alert(1)</script>'];

        $this->expectException(FirewallException::class);

        try {
            Shield::boot();
        } finally {
            foreach (glob($storage . '/*') ?: [] as $f) {
                @unlink($f);
            }

            @rmdir($storage);
        }
    }
}
