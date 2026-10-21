<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

/**
 * A session-state rule's answer that a request may not proceed.
 *
 * Browsers navigating to a page are sent to `$redirectUrl` when there is
 * one. Other AppFramework and OCS requests get 403 with
 * `{"error": $error}`, WebDAV requests 403 with the header `$davHeader:
 * required`.
 */
final class SessionBlock {
	public function __construct(
		/** Machine-readable, e.g. "password_change_required" */
		public readonly string $error,
		/** The header that tells WebDAV clients why, e.g. "X-Nextcloud-Password-Change" */
		public readonly string $davHeader,
		/** A short English sentence for WebDAV error bodies */
		public readonly string $message,
		/** Where a browser is sent to resolve the state; null to answer 403 there too */
		public readonly ?string $redirectUrl = null,
	) {
	}
}
