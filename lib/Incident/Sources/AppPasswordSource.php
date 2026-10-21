<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\IL10N;

/**
 * App passwords created in the period (from `ids_token_origin`, kept 30
 * days): by the account, or from the address. Only their ids, never the
 * app password itself.
 */
class AppPasswordSource implements ITimelineSource {
	public const KIND = 'app_password';

	public function __construct(
		private readonly TokenOriginMapper $origins,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('App passwords created')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		$rows = $this->origins->findInPeriod($query->uid, $query->address?->ip, $query->since, $query->until, $query->limit);
		foreach ($rows as $row) {
			$details = [];
			if ($row['ip'] !== null) {
				$details[] = $l->t('Created from the address %s.', [$row['ip']]);
			}
			$details[] = $row['session_token_id'] !== null
				? $l->t('It was created in a logged-in session (session %s).', [(string)$row['session_token_id']])
				: $l->t('Nextcloud did not record a session for it, for example because it was created on the command line or by connecting a device.');
			yield new TimelineEntry(
				id: 'app-password:' . $row['token_id'],
				at: $row['created_at'],
				kind: self::KIND,
				group: $l->t('App passwords created'),
				title: $query->isUser() ? $l->t('App password created') : $l->t('App password created for %s', [$row['uid']]),
				details: $details,
				address: $row['ip'],
				accounts: [$row['uid']],
				ref: ['type' => 'app_password', 'id' => (string)$row['token_id']],
				categories: [DataCategory::ConnectedDevices],
				followUp: $l->t('Check the app passwords created in this period with the account owner. Revoke the ones they do not recognise in their personal settings under Security.'),
			);
		}
	}
}
