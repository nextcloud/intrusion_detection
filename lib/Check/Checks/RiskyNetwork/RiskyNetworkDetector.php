<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\RiskyNetwork;

use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Risk\NetworkAttributes;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\SuccessfulLogin;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Records a password login from a hosting or Tor network as a
 * `risky_network` detection, merged per account, address and day, and runs its
 * responses. Whether the login needs extra confirmation is decided by the
 * step-up reason, which asks {@see NetworkAttributes} the same question.
 *
 * Apps and scripts that send the password (Basic auth) log in on every
 * request; with a memory cache, they are recorded once per account, address and day
 * without touching the database again.
 *
 * @template-implements IDetector<SuccessfulLogin>
 */
class RiskyNetworkDetector implements IDetector {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'risky-network';
	public const MERGE_WINDOW = 86400;

	public function __construct(
		private readonly NetworkAttributes $networks,
		private readonly SourceRepository $sources,
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
		private readonly Fingerprinter $fingerprinter,
	) {
	}

	/**
	 * @param SuccessfulLogin $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$login = $signal->login;
		$risky = $this->networks->riskyLogin($login);
		if ($risky === null) {
			return [];
		}
		if (!$login->interactive) {
			$key = 'rn:' . ($mode->acts() ? 'p' : 'o') . ':' . gmdate('Y-m-d', $this->timeFactory->getTime()) . ':' . $this->fingerprinter->lookup($login->uid(), $login->source?->ipKey ?? '');
			$cache = $this->caches->shared(self::CACHE);
			if ($cache !== null && !$cache->add($key, 1, self::MERGE_WINDOW)) {
				return [];
			}
		}
		$names = [];
		foreach ($risky->lists as $id) {
			$names[] = $this->sources->get($id)?->name ?? $id;
		}
		return [new DetectionDraft(
			checkId: RiskyNetwork::ID,
			source: $login->source,
			uid: $login->uid(),
			facts: new RiskyNetworkFacts(
				attributes: $risky->attributes,
				lists: $risky->lists,
				listNames: $names,
				client: !$login->interactive,
			),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			mergeWindow: self::MERGE_WINDOW,
			userAgent: $login->userAgent,
		)];
	}
}
