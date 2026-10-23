<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountLocked;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IL10N;

/**
 * The owner of an account's previous email address used the lock link
 * (concept section 11.15): the account was locked. Raised by
 * {@see \OCA\IntrusionDetection\Takeover\AccountLock}; it acts even in
 * learning mode, since locking was the owner's own decision, and tells all
 * administrators, who are the only ones who can unlock the account.
 */
final class AccountLocked implements ICheck, IExplainsDetection, IHeadlinesDetection, IExplainsToUser {
	public const ID = 'account_locked';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	/**
	 * The detection of a lock link that was used. It is recorded and told
	 * whatever the check's mode: the account holder locked their account.
	 *
	 * @param ?int $takeoverDetection the detection the link was sent for
	 * @param ?array<string, mixed> $change the email change the link was sent for
	 * @param list<array{id: int, name: string}> $ended the sessions and app passwords that were ended
	 * @param bool $keptEnabled the account was the last enabled administrator and stayed enabled
	 */
	public static function draft(?SourceKey $source, string $uid, int $linkId, string $sentTo, ?int $takeoverDetection, ?array $change, array $ended, bool $keptEnabled = false): DetectionDraft {
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			uid: $uid,
			facts: new AccountLockedFacts(
				link: $linkId,
				sentTo: $sentTo,
				newAddress: is_string($change['new_value_hint'] ?? null) ? $change['new_value_hint'] : null,
				changedAt: is_int($change['created_at'] ?? null) ? $change['created_at'] : null,
				changedFrom: is_string($change['ip'] ?? null) ? $change['ip'] : null,
				takeoverDetection: $takeoverDetection,
				tokensEnded: count($ended),
				ended: array_slice($ended, 0, 50),
				allAdmins: true,
				keptEnabled: $keptEnabled ? true : null,
			),
			mode: new ModeState(Mode::Protect, Mode::Protect),
		);
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::Critical,
			params: [],
			responses: [ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::NotifyAdmin],
			cost: CostClass::OnSecurityChange,
			stores: [DataKind::Detections, DataKind::LockLinks],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Account locked with the lock link'),
				shortName: $l->t('Account locked'),
				summary: $l->t('The owner of an account\'s previous email address locked the account.'),
				detects: $l->t('When an account\'s email address is changed as part of an account takeover sequence, the previous address gets a one-time link to lock the account. Someone used it: they say they did not make the change.'),
				decides: $l->t('Every session and app password of the account was ended, and the account was disabled. Only an administrator can enable it again.'),
				wrong: $l->t('Someone who still has access to an old mailbox of the user, or a user who forgot that they changed their address. Talk to the user before you enable the account again, and check its email address in the account management.'),
				data: $l->t('Detections: the account, the masked email addresses, the address the link was used from and what was done.'),
			),
			internal: true,
		);
	}

	#[\Override]
	public function headline(Detection $detection, IL10N $l): ?string {
		return $l->t('The account %s was locked by the owner of its previous email address', [(string)$detection->getUid()]);
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$sentTo = AccountLockedFacts::fromArray(DetectionFacts::of($detection)->facts)->sentTo;
		return new UserNotice(
			$l->t('Your account was locked'),
			[
				$sentTo !== ''
					? $l->t('Your account was locked with the link that Nextcloud sent to your previous email address %s after it was changed.', [$sentTo])
					: $l->t('Your account was locked with the link that Nextcloud sent to your previous email address after it was changed.'),
				$l->t('All your sessions and app passwords were ended, and your account was disabled until an administrator enabled it again.'),
			],
			[
				$l->t('Check the email address of your account and your devices and sessions in your security settings, and change your password.'),
			],
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = AccountLockedFacts::fromArray(DetectionFacts::of($detection)->facts);
		$uid = (string)$detection->getUid();
		$sentences = [$l->t('The account of %1$s was locked by the owner of the previous email address %2$s, with the link Nextcloud had sent there.', [$uid, $facts->sentTo])];
		$changedAt = $facts->changedAt ?? 0;
		if ($changedAt > 0) {
			$new = TextRenderer::defused($facts->newAddress ?? '');
			$ip = $facts->changedFrom ?? '';
			$sentences[] = match (true) {
				$new !== '' && $ip !== '' => $l->t('The address was changed to %1$s at %2$s from %3$s.', [$new, $this->dates->dateTime($changedAt), $ip]),
				$new !== '' => $l->t('The address was changed to %1$s at %2$s.', [$new, $this->dates->dateTime($changedAt)]),
				default => $l->t('The address was removed at %s.', [$this->dates->dateTime($changedAt)]),
			};
		}
		if ($detection->getIp() !== null) {
			$sentences[] = $l->t('The link was used from %s.', [$detection->getIp()]);
		}
		if ($facts->keptEnabled === true) {
			$sentences[] = $l->n(
				'%n session or app password was ended. The account was not disabled: it is the last enabled administrator, and only the command line could enable it again.',
				'%n sessions and app passwords were ended. The account was not disabled: it is the last enabled administrator, and only the command line could enable it again.',
				$facts->tokensEnded,
			);
			$sentences[] = $l->t('Talk to the user another way than by email now. If the account was taken over, reset its password with "occ user:resetpassword" and correct its email address.');
			return $sentences;
		}
		$sentences[] = $l->n(
			'%n session or app password was ended, and the account was disabled.',
			'%n sessions and app passwords were ended, and the account was disabled.',
			$facts->tokensEnded,
		);
		$sentences[] = $l->t('Talk to the user another way than by email before you enable the account again. Then use "Re-enable and start Secure my account", which requires a new password at the next login, and correct the email address in the account management if needed.');
		return $sentences;
	}
}
