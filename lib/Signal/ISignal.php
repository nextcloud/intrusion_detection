<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

/**
 * Something that happened, for the detectors to judge: a core event or a
 * finding of the app, as a small value object. Listeners and guards create
 * signals and hand them to {@see SignalDispatcher}.
 *
 * A signal that carries a secret (a password, the fingerprints of an
 * attempt) takes it as a #[\SensitiveParameter] and leaves it out of
 * __debugInfo(), and every parameter that takes a signal is sensitive.
 */
interface ISignal {
}
