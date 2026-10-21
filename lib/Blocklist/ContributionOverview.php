<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCP\IL10N;

/**
 * Read model of the shared blocklist contribution for the admin page: the
 * settings, the last run, the texts, and a live preview of the next payload.
 *
 * @psalm-import-type Payload from ContributionBatch
 * @psalm-type ContributionTexts = array{name: string, summary: string, sent: string, privacy: string, status: string}
 * @psalm-type ContributionView = array{
 *     enabled: bool,
 *     url: string,
 *     lastAttemptAt: ?int,
 *     lastSuccessAt: ?int,
 *     lastResult: ?string,
 *     lastError: ?string,
 *     lastReports: int,
 *     texts: ContributionTexts,
 *     preview: array{payload: Payload, reason: ?string, windowStart: int, windowEnd: int, truncated: bool},
 * }
 */
class ContributionOverview {
	public function __construct(
		private readonly ContributionSettings $config,
		private readonly BlocklistContribution $contribution,
	) {
	}

	/**
	 * @return ?ContributionView null while the feature is not available on this server
	 */
	public function get(IL10N $l): ?array {
		if (!$this->config->isAvailable()) {
			return null;
		}
		$batch = $this->contribution->preview();
		if ($batch->payload === null) {
			return null;
		}
		$state = $this->config->state();
		return [
			'enabled' => $this->config->isEnabled(),
			'url' => $this->config->url(),
			'lastAttemptAt' => $state->attemptAt,
			'lastSuccessAt' => $state->successAt,
			'lastResult' => $state->result,
			'lastError' => $state->error,
			'lastReports' => $state->reports,
			'texts' => self::texts($l, $batch->reason),
			'preview' => [
				'payload' => $batch->payload,
				'reason' => $batch->reason,
				'windowStart' => $batch->windowStart,
				'windowEnd' => $batch->windowEnd,
				'truncated' => $batch->truncated,
			],
		];
	}

	/**
	 * @return ContributionTexts
	 */
	public static function texts(IL10N $l, ?string $reason): array {
		return [
			'name' => $l->t('Contribute to a shared blocklist'),
			'summary' => $l->t('Once a day, Nextcloud can send the addresses it blocked because they used a decoy credential, requested a trap URL or tried a reserved login name. Other servers can then block these addresses before they are attacked.'),
			'sent' => $l->t('Only the address, the check that caught it, when it was first seen and how often are sent, for at most %s addresses a day. No user names, no user agents and nothing else about your users or your server. The server is identified by a random id, not by its instance id.', [(string)BlocklistContribution::MAX_REPORTS]),
			'privacy' => $l->t('IP addresses are personal data under the GDPR. Sending them to a shared blocklist passes personal data on to a third party, so you need a legal basis for it, usually a legitimate interest in protecting your server and others from attacks. Document this decision and mention it in your privacy notice before you switch this on.'),
			'status' => match ($reason) {
				null => $l->t('The next run sends the reports below.'),
				ContributionBatch::REASON_DISABLED => $l->t('Contributing is off, so nothing is sent. Once it is on, the next run sends the reports below.'),
				ContributionBatch::REASON_PROTECTION_OFF => $l->t('Intrusion detection is off, so nothing is sent.'),
				ContributionBatch::REASON_NO_URL => $l->t('No address to send the reports to is set, so nothing is sent.'),
				ContributionBatch::REASON_URL_REFUSED => $l->t('The address to send the reports to is refused, so nothing is sent. It must be an https:// address outside the local network, without a user name or password.'),
				ContributionBatch::REASON_NOTHING_NEW => $l->t('Nothing new was blocked since the last run, so nothing is sent.'),
				default => $l->t('Contributing to a shared blocklist is not available on this server.'),
			},
		];
	}
}
