<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\BlocklistMatch;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * A failed login from an address on a blocklist that did not refuse it (a
 * list in Observe, or the check observing).
 *
 * The lists come from the verdict the address check already has for this
 * request, so this adds no lookup. The login name and password are never
 * read. The names of the lists are stored, so the explanation still reads
 * well after a list was removed.
 *
 * @template-implements IDetector<FailedLogin>
 */
class BlocklistMatchDetector implements IDetector {
	public function __construct(
		private readonly RemoteAddressResolver $addresses,
		private readonly RequestContext $context,
		private readonly AddressCache $cache,
		private readonly SourceRepository $sources,
	) {
	}

	/**
	 * @param FailedLogin $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$source = $signal->source;
		if ($this->addresses->isIgnored($source)) {
			return [];
		}
		$verdict = $this->context->verdict() ?? $this->cache->get($source);
		if ($verdict === null) {
			return [];
		}
		$lists = [];
		foreach (BlocklistMatch::listsOf($verdict) as $id) {
			$lists[$id] = $this->sources->get($id)?->name ?? $id;
		}
		if ($lists === []) {
			return [];
		}
		return [new DetectionDraft(
			checkId: BlocklistMatch::ID,
			source: $source,
			facts: new BlocklistMatchFacts(lists: array_map('strval', array_keys($lists)), listNames: array_values($lists), trigger: BlocklistMatchFacts::TRIGGER_FAILED_LOGIN),
			merge: DetectionDraft::MERGE_SOURCE,
			mergeWindow: 3600,
			userAgent: $signal->userAgent,
		)];
	}
}
