<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\KnownDevice\IKnownDevices;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * Records a credential that was used from two networks at the same time
 * (concept section 10.12), once a login showed whose it is. Hits for the
 * same token within an hour are merged into one detection.
 *
 * The detection carries the token: `tokenId` for revoke_token and the
 * "No, it was not me" answer, `sessionTokenId` for a browser session. When
 * the check acts, the known device whose cookie came with this request is
 * forgotten: it may have been copied together with the session.
 *
 * @template-implements IDetector<CredentialSwitched>
 */
class TokenConcurrentUseDetector implements IDetector {
	public const MERGE_WINDOW = 3600;

	public function __construct(
		private readonly Tokens $tokens,
		private readonly IKnownDevices $knownDevices,
	) {
	}

	/**
	 * @param CredentialSwitched $signal
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): \Generator {
		$source = SourceKey::tryFromIp($signal->switch->currentIp);
		if ($source === null) {
			return;
		}
		$uid = $signal->user->getUID();
		$tokenId = $signal->tokenId;
		$token = $tokenId === null ? null : $this->tokens->find($uid, $tokenId);
		$switch = $signal->switch;
		$detection = yield new DetectionDraft(
			checkId: TokenConcurrentUse::ID,
			source: $source,
			uid: $uid,
			facts: new TokenConcurrentUseFacts(
				ip1: $switch->otherIp,
				net1: $switch->otherNet,
				ip2: $switch->currentIp,
				net2: $switch->currentNet,
				family: $switch->family,
				switches: $switch->switches,
				kind: $signal->kind,
				scheme: $signal->scheme,
				tokenName: $token === null ? '' : Tokens::name($token),
				tokenId: $tokenId,
				sessionTokenId: $signal->sessionTokenId,
				common: new CommonFacts(first: $switch->firstSwitchAt, last: $switch->at),
			),
			merge: DetectionDraft::MERGE_TOKEN,
			mergeWindow: self::MERGE_WINDOW,
			userAgent: $signal->userAgent,
			sessionTokenId: $signal->sessionTokenId,
			tokenId: $tokenId,
		);
		if ($detection !== null && $detection->isEnforced()) {
			$this->knownDevices->forgetCurrentDevice($uid, $detection->getId());
		}
	}
}
