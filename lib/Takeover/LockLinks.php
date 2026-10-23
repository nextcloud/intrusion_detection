<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Takeover\Db\LockLinkMapper;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Defaults;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Mail\IEMailTemplate;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use Psr\Log\LoggerInterface;

/**
 * The one-time "This wasn't me: lock my account" links (concept section
 * 11.15), emailed to the previous address of an account whose email was
 * changed in an account takeover sequence.
 *
 * - The token has about 256 bits (43 random letters and digits). Only a
 *   keyed fingerprint of it is stored; it is never logged, and it appears
 *   in nothing but the one email.
 * - A link works once and expires after {@see self::TTL}, or as soon as the
 *   account holder answers "Yes, it was me" about its detection.
 * - It can only lock the account, never unlock it or change anything else,
 *   so its worst misuse (someone who reads the old mailbox locks the
 *   account) is visible to the administrators and reversible.
 *
 * Opening the link changes nothing; see {@see AccountLock} for what using it does.
 *
 * @psalm-import-type SecurityChangeRow from SecurityChangeMapper
 */
class LockLinks implements IPurges {
	public const TTL = 7 * 86400;
	public const TOKEN_LENGTH = 43;
	public const ROUTE = Application::APP_ID . '.LockLink.show';

	public const SENT = 'sent';
	public const ALREADY_SENT = 'already_sent';
	public const NO_PREVIOUS_ADDRESS = 'no_previous_address';
	public const MAIL_FAILED = 'mail_failed';

	public const VALID = 'valid';
	public const USED = 'used';
	public const EXPIRED = 'expired';
	public const INVALID = 'invalid';

	public function __construct(
		private readonly LockLinkMapper $links,
		private readonly SecurityChangeMapper $changes,
		private readonly Fingerprinter $fingerprinter,
		private readonly ISecureRandom $random,
		private readonly ICrypto $crypto,
		private readonly Mails $mails,
		private readonly UserMessages $messages,
		private readonly DateFormatter $dates,
		private readonly IURLGenerator $urlGenerator,
		private readonly Defaults $defaults,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Delete the lock links that expired.
	 */
	#[\Override]
	public function purge(int $now): int {
		return $this->links->deleteExpired($now);
	}

	/**
	 * Email the previous address of an email change a lock link, once per
	 * detection.
	 *
	 * @return array{state: self::SENT|self::ALREADY_SENT|self::NO_PREVIOUS_ADDRESS|self::MAIL_FAILED, sentTo?: string, link?: int}
	 */
	public function send(IUser $user, int $changeId, int $detectionId): array {
		if ($this->links->existsForDetection($detectionId)) {
			return ['state' => self::ALREADY_SENT];
		}
		$change = $this->changes->find($changeId);
		$address = $change === null || $change['uid'] !== $user->getUID() ? null : $this->previousAddress($changeId);
		if ($change === null || $address === null) {
			return ['state' => self::NO_PREVIOUS_ADDRESS];
		}
		$token = $this->random->generate(self::TOKEN_LENGTH, ISecureRandom::CHAR_ALPHANUMERIC);
		$now = $this->timeFactory->getTime();
		$hint = EmailCodes::mask($address);
		$id = $this->links->insert($user->getUID(), $this->fingerprinter->lockToken($token), $hint, $detectionId, $changeId, $now, $now + self::TTL);
		$url = $this->urlGenerator->linkToRouteAbsolute(self::ROUTE, ['id' => $id, 'token' => $token]);
		$sent = $this->mails->sendTo($address, $user->getDisplayName(), $this->mail($user, $change, $url), $user->getUID());
		return ['state' => $sent ? self::SENT : self::MAIL_FAILED, 'sentTo' => $hint, 'link' => $id];
	}

	/**
	 * What state a link is in, if the token is the link's. A wrong token is
	 * indistinguishable from a link that does not exist.
	 *
	 * @return array{0: self::VALID|self::USED|self::EXPIRED|self::INVALID, 1: ?array{id: int, uid: string, sent_to_hint: string, detection_id: ?int, change_id: ?int, created_at: int, expires_at: int, used_at: ?int}}
	 */
	public function check(int $id, #[\SensitiveParameter] string $token): array {
		if (strlen($token) !== self::TOKEN_LENGTH || !ctype_alnum($token)) {
			return [self::INVALID, null];
		}
		$link = $this->links->find($id);
		if ($link === null || !hash_equals($link['token_hash'], $this->fingerprinter->lockToken($token))) {
			return [self::INVALID, null];
		}
		unset($link['token_hash'], $link['used_ip']);
		if ($link['used_at'] !== null) {
			return [self::USED, $link];
		}
		if ($link['expires_at'] <= $this->timeFactory->getTime()) {
			return [self::EXPIRED, $link];
		}
		return [self::VALID, $link];
	}

	/**
	 * End the open links sent about a detection, once the account holder
	 * said the takeover was them: whoever reads the old mailbox must no
	 * longer be able to lock the account.
	 *
	 * @return int how many links ended
	 */
	public function revokeForDetection(int $detectionId): int {
		return $this->links->revokeForDetection($detectionId, $this->timeFactory->getTime());
	}

	/**
	 * Use a valid link: only the first of concurrent requests succeeds.
	 */
	public function use(int $id, ?string $ip): bool {
		return $this->links->use($id, $this->timeFactory->getTime(), $ip);
	}

	private function previousAddress(int $changeId): ?string {
		$encrypted = $this->changes->notifyTo($changeId);
		if ($encrypted === null) {
			return null;
		}
		try {
			return SecurityChangeLog::address($this->crypto->decrypt($encrypted));
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not read a previous email address', ['exception' => $e]);
			return null;
		}
	}

	/**
	 * @param SecurityChangeRow $change
	 */
	private function mail(IUser $user, array $change, string $url): MailContent {
		$l = $this->messages->l10nFor($user);
		$when = $this->messages->asReader($user, $l, fn (): string => $this->dates->dateTime($change['created_at']));
		$server = $this->defaults->getName();
		return new MailContent(
			templateId: 'intrusion_detection.lockLink',
			subject: $l->t('Did you change the email address of your %s account?', [$server]),
			heading: $l->t('Did you change your email address?'),
			paragraphs: [
				$change['new_value_hint'] !== null
					? $l->t('The email address of your account %1$s on %2$s was changed to %3$s at %4$s. This message follows the notice about the change that %2$s may have sent you already.', [$user->getDisplayName(), $server, $change['new_value_hint'], $when])
					: $l->t('The email address of your account %1$s on %2$s was removed at %3$s. This message follows the notice about the change that %2$s may have sent you already.', [$user->getDisplayName(), $server, $when]),
				$l->t('Other security settings of the account were changed at about the same time.'),
				$l->t('If you did not change this, someone else may have access to your account. Use this link to lock your account immediately and alert your administrator.'),
			],
			buttonText: $l->t('Lock my account'),
			buttonUrl: $url,
			language: $l->getLanguageCode(),
			closing: [
				$l->t('Locking ends every session and app password of the account and disables it until an administrator enables it again. The link works once and expires in 7 days.'),
				$l->t('If you made the change yourself, ignore this email. Nothing happens unless you open the link and confirm.'),
			],
			notes: [['text' => $l->t('Only use the link if you did not make this change.'), 'label' => '', 'type' => IEMailTemplate::NOTE_WARNING]],
		);
	}
}
