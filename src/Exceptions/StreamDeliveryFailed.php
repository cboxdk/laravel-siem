<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Exceptions;

use RuntimeException;

/**
 * A batch could not be delivered to its destination (transport error, non-2xx
 * response, or a refused/SSRF-blocked endpoint). The message is already scrubbed
 * of any secret. The pump catches this to drive retry/backoff/dead-letter and the
 * circuit breaker.
 */
class StreamDeliveryFailed extends RuntimeException {}
