<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Adds what the cloud destinations (Datadog, S3, GCS) and the stream status need:
 *
 * - `options`           — the destination's typed, NON-secret settings (site,
 *                         bucket, region, prefix, …) as JSON. Secrets stay in the
 *                         encrypted `secret` column.
 * - `last_error`        — the latest delivery failure, already scrubbed of secrets.
 * - `last_failure_kind` — transient | authentication | configuration.
 * - `last_failure_at`   — when it happened.
 *
 * Every column is nullable with no default (a later host migration may convert
 * column types and refuse defaults), and each is added only if missing, so a
 * partially-applied run can simply be run again.
 */
return new class extends Migration
{
    public function up(): void
    {
        $columns = [
            'options' => static fn (Blueprint $table) => $table->json('options')->nullable(),
            'last_error' => static fn (Blueprint $table) => $table->text('last_error')->nullable(),
            'last_failure_kind' => static fn (Blueprint $table) => $table->string('last_failure_kind', 32)->nullable(),
            'last_failure_at' => static fn (Blueprint $table) => $table->timestamp('last_failure_at')->nullable(),
        ];

        foreach ($columns as $name => $add) {
            if (! Schema::hasColumn('log_streams', $name)) {
                Schema::table('log_streams', static function (Blueprint $table) use ($add): void {
                    $add($table);
                });
            }
        }
    }

    public function down(): void
    {
        foreach (['options', 'last_error', 'last_failure_kind', 'last_failure_at'] as $name) {
            if (Schema::hasColumn('log_streams', $name)) {
                Schema::table('log_streams', static function (Blueprint $table) use ($name): void {
                    $table->dropColumn($name);
                });
            }
        }
    }
};
