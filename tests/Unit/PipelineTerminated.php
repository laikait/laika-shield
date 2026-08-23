<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use RuntimeException;

/**
 * Stands in for the die() in ShieldPipeline::respond() so the block path can be
 * asserted in-process. Test-only.
 */
final class PipelineTerminated extends RuntimeException
{
}
