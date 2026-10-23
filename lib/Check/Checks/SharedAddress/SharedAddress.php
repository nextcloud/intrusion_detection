<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SharedAddress;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * Raised by the ban service's safety valve instead of a ban: the address is
 * used by many people at once, for example a company NAT or a misconfigured
 * reverse proxy, so blocking it would lock all of them out.
 */
final class SharedAddress implements ICheck {
	public const ID = 'shared_address';

	/**
	 * The detection for an address the safety valve kept from being blocked.
	 *
	 * @param string $wantedBy the check that wanted to block it
	 * @param bool $proxy whether it looks like a reverse proxy without trusted_proxies
	 */
	public static function draft(SourceKey $target, int $users, string $wantedBy, bool $proxy): DetectionDraft {
		return new DetectionDraft(
			checkId: self::ID,
			source: $target,
			facts: new SharedAddressFacts(users: $users, wantedBy: $wantedBy, proxy: $proxy ? true : null),
			merge: DetectionDraft::MERGE_SOURCE,
			mergeWindow: 86400,
		);
	}

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
				shortName: $l->t('Shared address'),
				summary: $l->t('An address would have been blocked, but many people log in from it.'),
				detects: $l->t('A check wanted to block an address from which several different people whose accounts are at least 3 days old logged in successfully in the last day. This is typical for an office network behind one address, or for a reverse proxy that is not configured as trusted, so that every visitor seems to come from the proxy.'),
				decides: $l->t('Fires instead of a block when at least {ban_shared_ip_users} different people whose accounts are at least 3 days old (or administrators) logged in successfully in the last 24 hours from the address (or, for a block of a whole network, from the network). Accounts registered in the last 3 days do not count, so nobody can keep their address from being blocked by creating a few. It also fires when the address is a private one most recent logins of different people with such accounts came from, or one an administrator logged in from within the last 7 days, while no trusted proxies are configured: then it is probably your reverse proxy.'),
				wrong: $l->t('If one address really is used by many people and attacked from inside, block it by hand. If every visitor seems to come from the same address, configure trusted proxies.'),
				data: $l->t('Successful logins: the address, the account and the hour, kept for 24 hours.'),
			),
			internal: true,
		);
	}
}
