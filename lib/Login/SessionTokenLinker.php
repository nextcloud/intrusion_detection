<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

/**
 * Links what a browser login recorded to the session's token. Core
 * creates the token only after the login event, so the recording leaves a
 * session marker ({@see SessionMarkers::LOGIN_HISTORY},
 * {@see SessionMarkers::LOGIN_DETECTIONS}), and its owner links it on the
 * session's first request.
 */
class SessionTokenLinker {
	public function __construct(
		private readonly SessionMarkers $markers,
		private readonly CoreSession $coreSession,
	) {
	}

	/**
	 * Hand a marker of the current account and the session's token id to
	 * `$link`, then drop the marker. A marker of another account, or one
	 * without a token to link to, is dropped without a link. When `$link`
	 * throws, the marker stays for the next request.
	 *
	 * @param \Closure(array<string, mixed>, int): void $link
	 */
	public function link(string $marker, ?string $currentUid, \Closure $link): void {
		$data = $this->markers->get($marker);
		if ($data === null) {
			return;
		}
		$tokenId = $currentUid !== null && ($data['uid'] ?? null) === $currentUid ? $this->coreSession->tokenId() : null;
		if ($tokenId !== null) {
			$link($data, $tokenId);
		}
		$this->markers->remove($marker);
	}
}
