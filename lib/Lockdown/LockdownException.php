<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Lockdown;

/**
 * A lockdown cannot be started because one is running, or cannot be
 * extended because none is.
 */
class LockdownException extends \RuntimeException {
}
