<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Tests;

use Cbox\LaravelSiem\LaravelSiemServiceProvider;
use Cbox\LaravelSiem\Testing\InteractsWithLogStreams;
use Cbox\Ssrf\SsrfServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    use InteractsWithLogStreams;

    protected function getPackageProviders($app): array
    {
        return [
            SsrfServiceProvider::class,
            LaravelSiemServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        tap($app->make(Repository::class), function (Repository $config): void {
            // A real encryption key so the `encrypted` secret cast round-trips.
            $config->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

            $config->set('database.default', 'testing');
            $config->set('database.connections.testing', [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ]);
        });
    }
}
