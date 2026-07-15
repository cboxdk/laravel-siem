<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

/**
 * Evaluates a stream's action allow/deny filter. The policy is a small bag:
 *
 *   ["allow" => ["user-login", "role-granted"]]  // only these actions ship
 *   ["deny"  => ["heartbeat"]]                    // everything except these
 *
 * When an `allow` list is present it is authoritative (deny-by-default within the
 * filter): an action not on it is rejected. A `deny` list rejects only its
 * members. No filter admits everything for that (already enabled) stream.
 */
class ActionFilter
{
    /**
     * @param  array<string, mixed>  $policy
     */
    public function admits(array $policy, string $action): bool
    {
        $allow = $this->list($policy, 'allow');

        if ($allow !== null && ! in_array($action, $allow, true)) {
            return false;
        }

        $deny = $this->list($policy, 'deny');

        if ($deny !== null && in_array($action, $deny, true)) {
            return false;
        }

        return true;
    }

    /**
     * @param  array<string, mixed>  $policy
     * @return list<string>|null
     */
    private function list(array $policy, string $key): ?array
    {
        $value = $policy[$key] ?? null;

        if (! is_array($value) || $value === []) {
            return null;
        }

        return array_values(array_filter($value, is_string(...)));
    }
}
