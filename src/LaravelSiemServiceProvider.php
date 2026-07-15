<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem;

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Jobs\PumpStreamDeliveries;
use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Cbox\Siem\Contracts\StreamSink;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

final class LaravelSiemServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/siem.php', 'siem');

        $this->app->singleton(LogStreams::class, DatabaseLogStreams::class);
        $this->app->singleton(StreamDispatcher::class, DatabaseStreamDispatcher::class);

        // The real egress sink. A host can rebind this contract to ship elsewhere.
        $this->app->singleton(StreamSink::class, HttpStreamSink::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/siem.php' => $this->app->configPath('siem.php'),
            ], 'siem-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => $this->app->databasePath('migrations'),
            ], 'siem-migrations');
        }

        $this->registerSchedule();
    }

    /**
     * Register the scheduled pump: every minute, dispatch a per-stream pump job for
     * every enabled stream (onto the configured queue). A host can turn this off
     * and drive delivery itself.
     */
    private function registerSchedule(): void
    {
        if (config('siem.schedule.enabled', true) !== true) {
            return;
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $schedule->call(function (): void {
                $connection = config('siem.queue.connection');
                $queue = config('siem.queue.queue', 'default');

                foreach ($this->app->make(LogStreams::class)->enabled() as $stream) {
                    PumpStreamDeliveries::dispatch($stream->id)
                        ->onConnection(is_string($connection) ? $connection : null)
                        ->onQueue(is_string($queue) ? $queue : null);
                }
            })
                ->everyMinute()
                ->name('cbox-siem:pump')
                ->withoutOverlapping();
        });
    }
}
