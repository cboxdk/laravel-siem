<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * Resolves a config-overridable Eloquent model class — FAIL-CLOSED.
 *
 * The delivery engine lets a host repoint its models via `config('siem.models.*')`,
 * which is exactly how an isolation-sensitive host (e.g. laravel-id) swaps in an
 * environment-owned subclass so every registry/dispatcher/pump query inherits a
 * hard tenant scope. Because the subclass and the base model share the same table,
 * silently falling back to the BASE model when the config is wrong would drop that
 * scope and return/write rows across every tenant — a deployment-wide, silent
 * fail-OPEN on the engine's most important boundary.
 *
 * So the rule is:
 *   - config unset (null)         → the base model (the intended standalone default);
 *   - config = a valid subclass   → that subclass;
 *   - config = anything else      → THROW. A truthy-but-wrong model config can only
 *                                   be a mistake, and it is never safe to guess.
 */
final class ModelClass
{
    /**
     * @template TModel of Model
     *
     * @param  class-string<TModel>  $base
     * @return class-string<TModel>
     */
    public static function resolve(string $configKey, string $base): string
    {
        $configured = config($configKey);

        // Unset → the base model is the intended default (standalone use).
        if ($configured === null) {
            return $base;
        }

        // Set to the base or a subclass of it → use it.
        if (is_string($configured) && is_a($configured, $base, true)) {
            return $configured;
        }

        // Set to something else → fail closed, loudly. Never downgrade to the base.
        throw new InvalidArgumentException(sprintf(
            "config('%s') must be null or a class extending %s; got %s. Refusing to "
            .'fall back to the base model, because a silent downgrade would drop any '
            .'tenant/environment isolation a host layered onto its subclass.',
            $configKey,
            $base,
            is_string($configured) ? $configured : get_debug_type($configured),
        ));
    }
}
