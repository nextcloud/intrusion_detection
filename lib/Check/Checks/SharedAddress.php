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
 * Raised by the ban service's safety valve instead of a ban: the address is
 * used by many people at once, for example a company NAT or a misconfigured
 * reverse proxy, so blocking it would lock all of them out.
 */
final class SharedAddress implements ICheck {
	public const ID = 'shared_address';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::High,
			params: [],
			responses: [ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::NotifyAdmin],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::SuccessfulLogins, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Shared address not blocked'),
				summary: $l->t('An address would have been blocked, but many people log in from it.'),
				detects: $l->t('A check wanted to block an address from which several different people logged in successfully in the last day. This is typical for an office network behind one address, or for a reverse proxy that is not configured as trusted, so that every visitor seems to come from the proxy.'),
				decides: $l->t('Fires instead of a block when at least {ban_shared_ip_users} different people logged in successfully in the last 24 hours from the address (or, for a block of a whole network, from the network). It also fires when the address is a private one most recent logins of different people came from while no trusted proxies are configured: then it is probably your reverse proxy.'),
				wrong: $l->t('If one address really is used by many people and attacked from inside, block it by hand. If every visitor seems to come from the same address, configure trusted proxies.'),
				data: $l->t('Successful logins: the address, the account and the hour, kept for 24 hours.'),
			),
			internal: true,
		);
	}
}
