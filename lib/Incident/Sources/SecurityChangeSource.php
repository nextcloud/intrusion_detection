<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\IL10N;

/**
 * Security changes in the period (from `ids_security_changes`): email
 * address, password, second factor, app passwords created and revoked, and
 * devices connected; of the account, or made from the address. Email
 * addresses appear only masked.
 */
class SecurityChangeSource implements ITimelineSource {
	public const KIND = 'security_change';

	public function __construct(
		private readonly SecurityChangeMapper $changes,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('Security changes')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		foreach ($this->changes->findInPeriod($query->uid, $query->address?->ip, $query->since, $query->until, $query->limit) as $row) {
			$type = SecurityChangeType::tryFrom($row['type']);
			if ($type === null) {
				continue;
			}
			$title = $type->label($l);
			$details = [];
			if ($type === SecurityChangeType::EmailChanged) {
				$details[] = $l->t('Previous address: %1$s. New address: %2$s.', [$row['old_value_hint'] ?? $l->t('none'), $row['new_value_hint'] ?? $l->t('none')]);
			} elseif ($row['detail'] !== null) {
				$details[] = in_array($type, [SecurityChangeType::SecondFactorAdded, SecurityChangeType::SecondFactorRemoved, SecurityChangeType::SecondFactorDisabled], true)
					? $l->t('Second factor: %s.', [$row['detail']])
					: $l->t('Name: "%s".', [$row['detail']]);
			}
			$details[] = match ($row['via']) {
				SecurityChangeLog::VIA_SELF => $l->t('Made in a session of the account itself.'),
				SecurityChangeLog::VIA_ADMIN => $l->t('Made by the administrator %s.', [(string)$row['actor_uid']]),
				SecurityChangeLog::VIA_OCC => $l->t('Made on the command line (occ).'),
				SecurityChangeLog::VIA_RESET => $l->t('Made through a password reset by email.'),
				default => $l->t('Made by Nextcloud itself or a background job.'),
			};
			if ($row['ip'] !== null) {
				$details[] = $l->t('From the address %s.', [$row['ip']]);
			}
			$own = $row['via'] === SecurityChangeLog::VIA_SELF;
			yield new TimelineEntry(
				id: 'security-change:' . $row['id'],
				at: $row['created_at'],
				kind: self::KIND,
				group: $l->t('Security changes'),
				title: $query->isUser() ? $title : $l->t('%1$s: %2$s', [$title, $row['uid']]),
				details: $details,
				address: $row['ip'],
				accounts: [$row['uid']],
				ref: ['type' => 'security_change', 'id' => (string)$row['id']],
				categories: $this->categories($type, $own),
				followUp: $own ? $this->followUp($type, $l) : null,
				measures: $type === SecurityChangeType::AppPasswordRevoked ? [$l->t('An app password of %1$s was revoked: "%2$s".', [$row['uid'], (string)$row['detail']])] : [],
			);
		}
	}

	/**
	 * @return list<DataCategory>
	 */
	private function categories(SecurityChangeType $type, bool $own): array {
		if (!$own) {
			return [];
		}
		return match ($type) {
			SecurityChangeType::AppPasswordCreated, SecurityChangeType::DeviceConnected => [DataCategory::ConnectedDevices],
			SecurityChangeType::AppPasswordRevoked => [],
			default => [DataCategory::AccountContent],
		};
	}

	private function followUp(SecurityChangeType $type, IL10N $l): ?string {
		return match ($type) {
			SecurityChangeType::EmailChanged => $l->t('Check with the account owner that they changed their email address themselves, and correct it in the account management if not.'),
			SecurityChangeType::SecondFactorRemoved, SecurityChangeType::SecondFactorDisabled => $l->t('Check with the account owner that they removed their second factor themselves, and ask them to set it up again if not.'),
			SecurityChangeType::PasswordChanged => $l->t('Check with the account owner that they changed their password themselves.'),
			SecurityChangeType::AppPasswordCreated, SecurityChangeType::DeviceConnected => $l->t('Check the app passwords and devices connected in this period with the account owner. Revoke the ones they do not recognise.'),
			default => null,
		};
	}
}
