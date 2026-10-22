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
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * A password login from a hosting provider's network or a Tor exit node
 * (concept section 10.17). It never blocks: the login needs extra
 * confirmation (step-up policy `risky_network`), and a low-severity
 * detection is kept, merged per account, address and day.
 *
 * The networks come from the network lists of the Blocks tab, which are
 * all off until an administrator switches one on: without a list the check
 * does nothing. The recording is {@see RiskyNetworkDetector}, the rule
 * {@see \OCA\IntrusionDetection\Risk\NetworkAttributes}, the confirmation
 * {@see \OCA\IntrusionDetection\Confirm\Reasons\RiskyNetworkReason}.
 */
final class RiskyNetwork implements ICheck, IExplainsDetection, IExplainsToUser {
	public const ID = 'risky_network';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::AddressesAndRequests,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [],
			responses: [ResponseType::StepUp, ResponseType::NotifyUser, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::StepUp],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::BlocklistRanges, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Hosting and Tor networks'),
				shortName: $l->t('Hosting or Tor login'),
				summary: $l->t('Asks for extra confirmation when someone logs in with their password from a cloud server or the Tor network.'),
				detects: $l->t('Attackers rarely try stolen passwords from home. They rent servers at cloud and hosting providers, or hide behind the Tor network. Most people log in from home, the office or a mobile network. A password login from a hosting provider or Tor is therefore suspicious, though it is no proof of an attack.'),
				decides: $l->t('Fires when someone logs in with their account password from an address on one of the network lists you switched on in the Blocks tab. Logins with app passwords never count, so sync clients and scripts in the cloud keep working. Addresses in your trusted networks ({risky_network_office_networks}), members of the exempt groups ({risky_network_exempt_groups}) and networks a user confirmed with "Yes, it was me" are never affected. Without a network list, this check does nothing.'),
				wrong: $l->t('People whose VPN or company proxy runs at a hosting provider, and people who use Tor for privacy. They are asked to confirm with their second factor or an email code; nothing is blocked. Add your company\'s VPN to the trusted networks, and put service accounts into an exempt group.'),
				data: $l->t('Detections: the address, the account and the kind of network, at most one per account, address and day. The network lists are stored like blocklists, with how often an address on them was seen.'),
				cost: $l->t('Nothing on normal requests: the network of an address is known from the same lookup that checks for blocks. Only at a password login from such a network are the trusted networks and exempt groups checked.'),
			),
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$uid = (string)$detection->getUid();
		$ip = (string)$detection->getIp();
		$names = $facts->list('listNames');
		$sentences = [];
		if (in_array('tor', $facts->list('attributes'), true)) {
			$sentences[] = $l->t('The account %1$s logged in with its password from %2$s, a Tor exit node.', [$uid, $ip]);
		} elseif ($names !== []) {
			$sentences[] = $l->t('The account %1$s logged in with its password from %2$s, an address of a cloud or hosting provider (%3$s).', [$uid, $ip, implode(', ', $names)]);
		} else {
			$sentences[] = $l->t('The account %1$s logged in with its password from %2$s, an address of a cloud or hosting provider.', [$uid, $ip]);
		}
		if ($facts->bool('client')) {
			$sentences[] = $l->t('It was an app or a script that sends the password with its requests, not the login page.');
		}
		$sentences[] = $l->t('Such logins are suspicious, not proof of an attack: attackers often use rented servers or Tor, but so do some VPNs.');
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It happened %n time within a day.', 'It happened %n times within a day.', $detection->getHits());
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		$ip = (string)$detection->getIp();
		return new UserNotice(
			$l->t('Login from a hosting or Tor network'),
			[
				in_array('tor', $facts->list('attributes'), true)
					? $l->t('Someone logged in to your account with your password from %s, an address of the Tor network.', [$ip])
					: $l->t('Someone logged in to your account with your password from %s, an address of a cloud or hosting provider.', [$ip]),
			],
			[$l->t('If this was you, for example through a VPN, there is nothing to do. If it was not you, change your password now and check your devices in your security settings.')],
		);
	}
}
