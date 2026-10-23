<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\DecoyCredential;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\DigestSection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCP\IL10N;

/**
 * A planted decoy credential was used. The administrator put it where only
 * an intruder finds it, so this check acts even during learning mode.
 * The detector is {@see DecoyCredentialDetector}; the decoys are managed by
 * {@see \OCA\IntrusionDetection\Decoy\DecoyService}.
 */
final class DecoyCredential implements ICheck, IExplainsDetection {
	public const ID = 'decoy_credential';

	/** A use of the secret blocks at this escalation level at once */
	public const BAN_LEVEL = 3;

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Traps,
			defaultMode: Mode::Protect,
			severity: Severity::Critical,
			params: [],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::Decoys, DataKind::Detections, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Decoy app passwords and tokens'),
				shortName: $l->t('Decoy credential used'),
				summary: $l->t('Someone used a fake credential that you planted.'),
				detects: $l->t('You create a decoy app password or token and leave it where only an intruder would look: an old script on a file server, a wiki page about backups, a note in a shared drive. It opens nothing, and nobody has a reason to use it, so whoever does found it where you put it.'),
				decides: $l->t('Fires at the first login with a decoy\'s secret, whatever account name comes with it. A login with a decoy\'s account name and another password counts as a weaker sign. Unlike checks that block, it acts during learning mode as well.'),
				wrong: $l->t('Practically never: the secrets are random and exist nowhere but where you planted them. If a decoy fires, find out who could read the place where it was.'),
				data: $l->t('Decoys: the label, the optional account name and a keyed fingerprint of the secret. The secret itself is shown once and never stored. Detections: the address, the decoy\'s label and the time.'),
			),
			actsWhileLearning: true,
			digestSection: DigestSection::Decoys,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DecoyCredentialFacts::fromArray(DetectionFacts::of($detection)->facts);
		$sentences = $facts->match === DecoyCredentialMatch::LoginName
			? [
				$l->t('The address %1$s tried to log in with the account name of the decoy "%2$s", but not with its secret.', [(string)$detection->getIp(), $facts->label]),
				$l->t('Someone has seen where the decoy is planted, or guessed the name. This is a weaker sign than using the secret.'),
			]
			: [
				$l->t('The address %1$s used the decoy credential "%2$s".', [(string)$detection->getIp(), $facts->label]),
				$l->t('It was planted on purpose and is never used legitimately, so whoever used it found it where it was placed.'),
			];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It was used %n time between %1$s and %2$s.', 'It was used %n times between %1$s and %2$s.', $detection->getHits(), [
				$this->dates->dateTime($detection->getCreatedTime()),
				$this->dates->time($detection->getLastSeenAt()),
			]);
		}
		return $sentences;
	}
}
