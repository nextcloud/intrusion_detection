<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\SyncFailure;
use OCA\IntrusionDetection\Blocklist\SyncResult;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportException;
use OCA\IntrusionDetection\Export\FirewallExporter;
use OCA\IntrusionDetection\Export\FirewallSnippets;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * The firewall export and the blocklists as the Blocks tab shows them.
 *
 * @psalm-import-type IntrusionDetectionFirewallExport from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBlocklists from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBlocklist from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSyncResult from ResponseDefinitions
 */
class BlocklistPresenter {
	/** Days of matches shown per list */
	public const MATCH_DAYS = 14;

	public function __construct(
		private readonly FirewallExporter $exporter,
		private readonly FirewallSnippets $snippets,
		private readonly BlocklistOverview $overview,
		private readonly SourceRepository $sources,
		private readonly CheckSummary $checks,
	) {
	}

	/**
	 * @return IntrusionDetectionFirewallExport
	 */
	public function export(IL10N $l): array {
		$status = $this->exporter->status()->toArray();
		$snippets = [];
		foreach ($this->snippets->all() as $id => $snippet) {
			$snippets[] = ['id' => $id, 'file' => $snippet['file'], 'content' => $snippet['content']];
		}
		return [
			'directory' => $status['directory'],
			'active' => $status['active'],
			'formats' => $status['formats'],
			'files' => $status['files'],
			'lastWriteAt' => $status['lastWriteAt'],
			'error' => $status['error'],
			'errorText' => $status['error'] === null ? null : ExportException::describe($status['error'], $l),
			'errorAt' => $status['errorAt'],
			'entries' => $status['entries'],
			'configKey' => ExportDirectory::CONFIG_KEY,
			'snippetsUseDirectory' => $this->snippets->usesConfiguredDirectory(),
			'exampleDirectory' => FirewallSnippets::EXAMPLE_DIR,
			'snippets' => $snippets,
		];
	}

	/**
	 * @return IntrusionDetectionBlocklists
	 */
	public function lists(IL10N $l): array {
		$matches = $this->overview->matches(self::MATCH_DAYS);
		$lists = [];
		foreach ($this->overview->lists() as $list) {
			$source = $this->sources->get($list['id']);
			$lists[] = [
				'id' => $list['id'],
				'name' => $list['name'],
				'url' => $list['url'],
				'format' => $list['format'],
				'purpose' => $list['purpose'],
				'mode' => $list['mode'],
				'enabled' => $list['enabled'],
				'builtin' => $list['builtin'],
				'interval' => $list['interval'],
				'customInterval' => $source !== null && $source->interval !== null,
				'termsUrl' => $list['termsUrl'],
				'sha256' => $source?->sha256,
				'reference' => $list['reference'],
				'ranges' => $list['ranges'],
				'entries' => $list['entries'],
				'skipped' => $list['skipped'],
				'lastAttemptAt' => $list['lastAttemptAt'],
				'lastSuccessAt' => $list['lastSuccessAt'],
				'lastFailureAt' => $list['lastFailureAt'],
				'lastError' => $list['lastError'],
				'lastErrorText' => $list['lastError'] === null ? null : SyncFailure::describe($list['lastError'], $l, $list['url'], $list['lastErrorStatus']),
				'failures' => $list['failures'],
				'stale' => $list['stale'],
				'matches' => $matches[$list['id']] ?? [],
			];
		}
		return [
			'lists' => $lists,
			'countsMatches' => $this->overview->countsMatches(),
			'matchDays' => self::MATCH_DAYS,
			'check' => $this->checks->of(BlocklistMatch::ID, $l),
			'networkCheck' => $this->checks->of(RiskyNetwork::ID, $l),
			'maxLists' => SourceRepository::MAX_SOURCES,
			'minInterval' => BlocklistSource::MIN_INTERVAL,
			'maxInterval' => BlocklistSource::MAX_INTERVAL,
			'formats' => array_map(static fn (ListFormat $f): string => $f->value, ListFormat::cases()),
		];
	}

	/**
	 * @return IntrusionDetectionBlocklist|null
	 */
	public function list(string $id, IL10N $l): ?array {
		foreach ($this->lists($l)['lists'] as $list) {
			if ($list['id'] === $id) {
				return $list;
			}
		}
		return null;
	}

	/**
	 * @return IntrusionDetectionSyncResult
	 */
	public static function syncResult(SyncResult $result, IL10N $l, string $url): array {
		return [
			'list' => $result->listId,
			'outcome' => $result->outcome,
			'error' => $result->error,
			'errorText' => $result->error === null ? null : SyncFailure::describe($result->error, $l, $url, $result->status),
			'ranges' => $result->ranges,
		];
	}
}
