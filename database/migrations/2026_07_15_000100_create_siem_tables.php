<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('log_streams', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('name');
            $table->string('destination');
            $table->string('endpoint_url');
            // Ciphertext of the HEC/bearer token or HMAC key (Laravel `encrypted`
            // cast). `text` because the ciphertext is far larger than the secret.
            $table->text('secret')->nullable();
            $table->string('auth')->default('none');
            // The uninterpreted host-scoping seam (environment/org/team). Nullable
            // and index-only: the package assigns it no meaning.
            $table->string('owner_key')->nullable()->index();
            $table->json('filters')->nullable();
            $table->json('redaction')->nullable();
            $table->boolean('enabled')->default(true)->index();
            // Health state for the per-stream circuit breaker.
            $table->timestamp('last_success_at')->nullable();
            $table->unsignedInteger('consecutive_failures')->default(0);
            $table->timestamp('circuit_opened_at')->nullable();
            $table->timestamps();
        });

        Schema::create('stream_deliveries', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('stream_id')->index();
            $table->json('payload');
            $table->string('status')->default('pending');
            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('next_attempt_at')->nullable();
            $table->text('last_error')->nullable();
            $table->timestamp('delivered_at')->nullable();
            $table->timestamps();

            // The pump's claim query: pending rows for a stream that are due.
            $table->index(['stream_id', 'status', 'next_attempt_at'], 'stream_deliveries_claim_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('stream_deliveries');
        Schema::dropIfExists('log_streams');
    }
};
