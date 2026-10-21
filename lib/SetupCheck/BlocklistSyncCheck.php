<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use OCA\IntrusionDetection\Blocklist\SyncFailure;
use OCP\IL10N;
use OCP\SetupCheck\ISetupCheck;
use OCP\SetupCheck\SetupResult;

/**
 * Warns when an enabled blocklist or network list has not been downloaded
 * successfully for more than three of its intervals. The last good version
 * stays in use meanwhile, but it gets older.
 */
class BlocklistSyncCheck implements ISetupCheck {
	public function __construct(
		private readonly BlocklistOverview $overview,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection blocklists');
	}

	#[\Override]
	public function getCategory(): string {
		return 'security';
	}

	#[\Override]
	public function run(): SetupResult {
		$stale = $this->overview->stale();
		if ($stale === []) {
			return SetupResult::success($this->l->t('Every enabled list was downloaded recently.'));
		}
		$lines = [];
		foreach ($stale as $list) {
			$lines[] = $this->l->t('%1$s: %2$s', [$list['name'], $this->describe($list['lastError'])]);
		}
		return SetupResult::warning(
			$this->l->n(
				'%n list could not be downloaded for more than three sync intervals, so an old version of it is in use: %s. Run "occ intrusion:blocklists:sync" to see the error.',
				'%n lists could not be downloaded for more than three sync intervals, so old versions of them are in use: %s. Run "occ intrusion:blocklists:sync" to see the errors.',
				count($stale),
				[implode('; ', $lines)],
			),
		);
	}

	private function describe(?string $error): string {
		return match ($error) {
			SyncFailure::URL_REFUSED => $this->l->t('the address is refused (not https, or in the local network)'),
			SyncFailure::HTTP => $this->l->t('the server answered with an error'),
			SyncFailure::TOO_LARGE => $this->l->t('the file is larger than 10 MB'),
			SyncFailure::INVALID_FORMAT => $this->l->t('the file is not in the expected format'),
			SyncFailure::EMPTY => $this->l->t('the file contains no address ranges'),
			SyncFailure::TOO_MANY_ENTRIES => $this->l->t('the list has more entries than allowed'),
			SyncFailure::TOO_MANY_MALFORMED => $this->l->t('more than one in a hundred entries are not address ranges'),
			default => $this->l->t('the download failed'),
		};
	}
}
