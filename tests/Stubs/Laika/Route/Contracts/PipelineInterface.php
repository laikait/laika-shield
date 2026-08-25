<?php

declare(strict_types=1);

namespace Laika\Route\Contracts;

/**
 * Test stub for the laika-framework pipeline contract.
 *
 * laika-framework REQUIRES laika-shield, so this package can never depend on the
 * framework back — that would close a framework -> shield -> framework cycle in
 * Composer. The real interface is therefore absent from this repo's standalone
 * install, and classes implementing it cannot be autoloaded by the test suite.
 *
 * This stub exists only under autoload-dev so those classes can load. It must stay
 * signature-identical to the framework's interface; ShieldPipelineTest asserts the
 * shape by reflection so drift is caught here rather than in production.
 *
 * Its NAMESPACE has to track the framework too, not just the signature. When the
 * real interface moved from Laika\Route\Interfaces to Laika\Route\Contracts and this
 * file did not follow, every test touching ShieldPipeline died with
 * "Interface ... not found" -- the class could not be autoloaded at all.
 */
interface PipelineInterface
{
    /**
     * @param callable $next
     * @param array<string,mixed> $params
     * @return ?string
     */
    public function handle(callable $next, array &$params): ?string;
}
