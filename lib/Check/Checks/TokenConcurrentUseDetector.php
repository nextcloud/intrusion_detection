<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\CredentialUse\CredentialSwitch;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\KnownDevice\IKnownDevices;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\Tokens;
use OCP\IUser;

/**
 * Records a credential that was used from two networks at the same time
 * (concept section 10.12), once a login showed whose it is. Hits for the
 * same token within an hour are merged into one detection.
 *
 * The detection carries the token: `tokenId` for revoke_token and the
 * "No, it was not me" answer, `sessionTokenId` for a browser session. When
 * the check acts, the known device whose cookie came with this request is
 * forgotten: it may have been copied together with the session.
 */
class TokenConcurrentUseDetector {
	public const MERGE_WINDOW = 3600;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly ResponseEngine $engine,
		private readonly Tokens $tokens,
		private readonly IKnownDevices $knownDevices,
	) {
	}

	/**
	 * @param TokenConcurrentUse::KIND_* $kind
	 * @param PresentedCredential::SCHEME_* $scheme
	 * @param ?int $tokenId the app password or session token that was used
	 * @param ?int $sessionTokenId the browser session's token, if one is involved
	 */
	public function record(CredentialSwitch $switch, string $kind, string $scheme, IUser $user, ?int $tokenId, ?int $sessionTokenId, ?string $userAgent): ?Detection {
		if (!$this->settings->modeState(TokenConcurrentUse::ID)->runs()) {
			return null;
		}
		$source = SourceKey::tryFromIp($switch->currentIp);
		if ($source === null) {
			return null;
		}
		$uid = $user->getUID();
		$token = $tokenId === null ? null : $this->tokens->find($uid, $tokenId);
		$detection = $this->engine->handle(new DetectionDraft(
			checkId: TokenConcurrentUse::ID,
			source: $source,
			uid: $uid,
			facts: $switch->facts() + [
				'kind' => $kind,
				'scheme' => $scheme,
				'tokenName' => $token === null ? '' : Tokens::name($token),
				'tokenId' => $tokenId,
				'sessionTokenId' => $sessionTokenId,
			],
			merge: DetectionDraft::MERGE_TOKEN,
			mergeWindow: self::MERGE_WINDOW,
			userAgent: $userAgent,
			sessionTokenId: $sessionTokenId,
			tokenId: $tokenId,
		));
		if ($detection !== null && $detection->isEnforced()) {
			$this->knownDevices->forgetCurrentDevice($uid, $detection->getId());
		}
		return $detection;
	}
}
