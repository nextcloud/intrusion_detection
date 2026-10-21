<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * Requests from addresses on external blocklists.
 *
 * The blocking itself happens in the address check, from the verdict
 * ({@see \OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider}): there is
 * no detection per request. A failed login from an address on a list is
 * recorded as a low-severity detection, merged per address and hour.
 */
final class BlocklistMatch implements ICheck, IExplainsDetection {
	public const ID = 'blocklist_match';
	public const ATTRIBUTE_PREFIX = 'list:';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::AddressesAndRequests,
			defaultMode: Mode::Off,
			severity: Severity::Low,
			params: [],
			responses: [ResponseType::FlagSource, ResponseType::NotifyAdmin],
			defaultResponses: [],
			cost: CostClass::ExternalCall,
			stores: [DataKind::BlocklistRanges, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Known bad addresses'),
				summary: $l->t('Refuses requests from networks on public blocklists, such as Spamhaus DROP.'),
				detects: $l->t('Some organisations publish lists of networks that are run by criminals or send nothing but attacks. Nextcloud can download such lists and refuse every request from these networks, before they can try a single password.'),
				decides: $l->t('Every list you switch on is downloaded every {blocklist_sync_interval}. A list set to Protect refuses all requests from an address on it. A list set to Observe only counts them. A failed login from an address on a list is recorded, at most once per address and hour. Lists with more than {blocklist_max_entries} entries are not used.'),
				wrong: $l->t('A list can contain a network that honest people use, for example after it changed hands. Add such addresses to the brute-force allowlist, which always wins, or set the list to Observe. Private and local networks are never taken from a list.'),
				data: $l->t('The downloaded address ranges. Per list and day, how often an address on the list was seen, and the last 20 of these addresses. Downloading a list sends no data about your server.'),
			),
		);
	}

	/**
	 * The lists an address is on but was not refused by, from its verdict.
	 *
	 * @return list<string> list ids
	 */
	public static function listsOf(Verdict $verdict): array {
		$ids = [];
		foreach ($verdict->attributes as $attribute) {
			if (str_starts_with($attribute, self::ATTRIBUTE_PREFIX)) {
				$ids[] = substr($attribute, strlen(self::ATTRIBUTE_PREFIX));
			}
		}
		return $ids;
	}

	/**
	 * The detection for a failed login from an address on the given lists.
	 * The names are stored, so the explanation still reads well after a list
	 * was removed.
	 *
	 * @param array<string, string> $lists names keyed by list id
	 */
	public function failedLoginDraft(SourceKey $source, array $lists, ?string $userAgent): DetectionDraft {
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: ['lists' => array_keys($lists), 'listNames' => array_values($lists), 'trigger' => 'failed_login'],
			merge: DetectionDraft::MERGE_SOURCE,
			mergeWindow: 3600,
			userAgent: $userAgent,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = $detection->getExplanationData()['facts'] ?? [];
		$names = is_array($facts) && is_array($facts['listNames'] ?? null) ? array_filter($facts['listNames'], 'is_string') : [];
		$sentences = [
			$l->t('A login failed from %1$s, an address on these blocklists: %2$s.', [(string)$detection->getIp(), implode(', ', $names)]),
		];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It happened %n time.', 'It happened %n times.', $detection->getHits());
		}
		$sentences[] = $l->t('Requests from this address were not refused, because the list is set to Observe, or because the check only observes.');
		return $sentences;
	}
}
