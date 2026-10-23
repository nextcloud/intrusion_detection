<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\IL10N;

/**
 * What the "Manage" part of the user's security page has to offer: the
 * remembered devices, the trusted networks, and the other browser sessions
 * that "Log out other browsers" would end. The page leaves the part out
 * while all three are none.
 */
class ManageSummary {
	public function __construct(
		private readonly KnownDevices $knownDevices,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly Tokens $tokens,
		private readonly CoreSession $coreSession,
	) {
	}

	/**
	 * @return array{devices: int, networks: int, otherBrowsers: int}
	 */
	public function forUser(string $uid, IL10N $l): array {
		return [
			'devices' => count($this->knownDevices->forUser($uid, $l)),
			'networks' => count($this->trustedNetworks->forUser($uid)),
			'otherBrowsers' => $this->tokens->countSessionsExcept($uid, $this->coreSession->tokenId()),
		];
	}
}
