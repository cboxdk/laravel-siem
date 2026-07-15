<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Tests\Fixtures;

use Cbox\LaravelSiem\Testing\InteractsWithLogStreams;
use Orchestra\Testbench\TestCase;

/**
 * A composition site so PHPStan analyses the shippable {@see InteractsWithLogStreams}
 * trait (a trait is only analysed where it is used). Mirrors how a host wires the
 * trait into its own Testbench-based `TestCase`.
 */
class InteractsWithLogStreamsFixture extends TestCase
{
    use InteractsWithLogStreams;
}
