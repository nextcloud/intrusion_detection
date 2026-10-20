<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCP\IL10N;

/**
 * Blocks an administrator added by hand (admin page or occ).
 */
final class ManualBlock implements ICheck {
	public const ID = 'manual';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [],
			responses: [ResponseType::Ban],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::Background,
			stores: [DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Blocked by an administrator'),
				summary: $l->t('An administrator blocked this address by hand.'),
				detects: $l->t('Nothing: an administrator added the block on the admin page or with occ.'),
				decides: $l->t('The block lasts as long as the administrator chose.'),
				wrong: $l->t('Lift the block on the Blocks tab or with occ intrusion:bans:lift.'),
				data: $l->t('The blocked address or network, who blocked it, the note, and when it expires.'),
			),
			internal: true,
		);
	}
}
