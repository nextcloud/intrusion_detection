<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IUser;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;

/**
 * The 6-digit codes that confirm a login by email (concept section 11.5).
 *
 * A code comes from {@see ISecureRandom}; only its {@see IHasher} hash is
 * kept, in the session's step-up state, and it is valid TTL seconds. A
 * login gets MAX_ATTEMPTS tries in all and MAX_RESENDS new codes per
 * RESEND_WINDOW. An account gets at most MAX_MAILS codes per MAIL_WINDOW
 * across all its logins, so that apps or an attacker with the password
 * cannot flood its mailbox, and MAX_WRONG wrong codes per MAIL_WINDOW
 * across all its logins, so that new logins bring no new tries: once
 * they are used up, no code is sent or checked until the window passes. The tries are counted on the server too
 * ({@see UnconfirmedSessions::takeCodeAttempt()}), before the code is
 * checked: parallel requests that each read the session before any of them
 * saved it never get more tries between them. The code is in the email and nowhere else: never in a
 * log line, a table, a notification or the session in plain text.
 */
class EmailCodes {
	public const LENGTH = 6;
	public const TTL = 600;
	public const MAX_ATTEMPTS = 5;
	public const MAX_RESENDS = 3;
	public const RESEND_WINDOW = 600;
	public const MAX_MAILS = 5;
	public const MAIL_WINDOW = 3600;
	public const MAX_WRONG = 10;

	public const VERIFIED = 'verified';
	public const WRONG = 'wrong';
	public const EXPIRED = 'expired';
	/** Not six digits: not counted as an attempt */
	public const MALFORMED = 'malformed';
	/** No tries left */
	public const EXHAUSTED = 'exhausted';

	public function __construct(
		private readonly ISecureRandom $random,
		private readonly IHasher $hasher,
		private readonly Mails $mails,
		private readonly UserMessages $messages,
		private readonly ITimeFactory $timeFactory,
		private readonly LoginConfirmationStore $store,
		private readonly IUserConfig $userConfig,
	) {
	}

	/**
	 * Send a new code. The earlier code, if any, stops working.
	 *
	 * @return StepUpState with the new code; with none when the email was not handed to the mail server or the account got too many codes
	 */
	public function issue(IUser $user, StepUpState $state): StepUpState {
		$state = $state->withCode(null, 0);
		$sent = $this->recentMails($user->getUID());
		if (count($sent) >= self::MAX_MAILS) {
			return $state;
		}
		$code = $this->random->generate(self::LENGTH, ISecureRandom::CHAR_DIGITS);
		if (!$this->mails->send($user, $this->mail($user, $state, $code))) {
			return $state;
		}
		$this->userConfig->setValueArray($user->getUID(), Application::APP_ID, UserKeys::CODE_MAILS, [...$sent, $this->timeFactory->getTime()], lazy: true);
		return $state->withCode($this->hasher->hash($code), $this->timeFactory->getTime() + self::TTL);
	}

	/**
	 * Whether the account got MAX_MAILS codes within MAIL_WINDOW.
	 */
	public function isLimited(IUser $user): bool {
		return count($this->recentMails($user->getUID())) >= self::MAX_MAILS;
	}

	/**
	 * Whether MAX_WRONG wrong codes were entered for the account within MAIL_WINDOW.
	 */
	public function isGuessLimited(string $uid): bool {
		return count($this->recentWrong($uid)) >= self::MAX_WRONG;
	}

	/**
	 * Whether another code may be sent now.
	 */
	public function canResend(StepUpState $state): bool {
		return count($this->recentResends($state)) < self::MAX_RESENDS;
	}

	/**
	 * Send another code, if the limit allows it.
	 *
	 * @return ?StepUpState null when the limit does not allow it; else as {@see self::issue()}
	 */
	public function resend(IUser $user, StepUpState $state): ?StepUpState {
		if (!$this->canResend($state)) {
			return null;
		}
		return $this->issue($user, $state->withResends([...$this->recentResends($state), $this->timeFactory->getTime()]));
	}

	/**
	 * Check an entered code. A wrong code counts as an attempt; a correct
	 * one is used up.
	 *
	 * @return array{0: self::VERIFIED|self::WRONG|self::EXPIRED|self::MALFORMED|self::EXHAUSTED, 1: StepUpState} the result, and the state with the attempt counted or the code used up
	 */
	public function verify(StepUpState $state, #[\SensitiveParameter] string $input): array {
		if ($state->attempts >= self::MAX_ATTEMPTS || $this->isGuessLimited($state->uid)) {
			return [self::EXHAUSTED, $state];
		}
		$code = preg_replace('/[\s-]+/', '', $input) ?? '';
		if (preg_match('/^\d{' . self::LENGTH . '}$/', $code) !== 1) {
			return [self::MALFORMED, $state];
		}
		if ($state->codeHash === null || $state->codeExpires <= $this->timeFactory->getTime()) {
			return [self::EXPIRED, $state];
		}
		$used = $this->store->takeCodeAttempt(self::MAX_ATTEMPTS);
		if ($used === null) {
			return [self::EXHAUSTED, $state->withAttempts(self::MAX_ATTEMPTS)];
		}
		// The tries before this one, as the server counted them.
		$state = $state->withAttempts(max($state->attempts, $used - 1));
		if (!$this->hasher->verify($code, $state->codeHash)) {
			$state = $state->withAttempts($state->attempts + 1);
			$wrong = [...$this->recentWrong($state->uid), $this->timeFactory->getTime()];
			$this->userConfig->setValueArray($state->uid, Application::APP_ID, UserKeys::CODE_WRONG, $wrong, lazy: true);
			return [$state->attempts >= self::MAX_ATTEMPTS || count($wrong) >= self::MAX_WRONG ? self::EXHAUSTED : self::WRONG, $state];
		}
		return [self::VERIFIED, $state->withCode(null, 0)];
	}

	public function attemptsLeft(StepUpState $state): int {
		return max(0, self::MAX_ATTEMPTS - $state->attempts);
	}

	/**
	 * An email address as the verify page shows it: the first character of
	 * the local part, then "***", then the domain (f***@example.com).
	 */
	public static function mask(string $address): string {
		$at = strrpos($address, '@');
		if ($at === false || $at === 0) {
			return '***';
		}
		return mb_substr(substr($address, 0, $at), 0, 1) . '***' . substr($address, $at);
	}

	/**
	 * @return list<int> when the account's codes of the last MAIL_WINDOW were sent
	 */
	private function recentMails(string $uid): array {
		$since = $this->timeFactory->getTime() - self::MAIL_WINDOW;
		$sent = $this->userConfig->getValueArray($uid, Application::APP_ID, UserKeys::CODE_MAILS, lazy: true);
		return array_values(array_filter($sent, static fn (mixed $at): bool => is_int($at) && $at > $since));
	}

	/**
	 * @return list<int> when the account's wrong codes of the last MAIL_WINDOW were entered
	 */
	private function recentWrong(string $uid): array {
		$since = $this->timeFactory->getTime() - self::MAIL_WINDOW;
		$wrong = $this->userConfig->getValueArray($uid, Application::APP_ID, UserKeys::CODE_WRONG, lazy: true);
		return array_values(array_filter($wrong, static fn (mixed $at): bool => is_int($at) && $at > $since));
	}

	/**
	 * @return list<int>
	 */
	private function recentResends(StepUpState $state): array {
		$since = $this->timeFactory->getTime() - self::RESEND_WINDOW;
		return array_values(array_filter($state->resends, static fn (int $at): bool => $at > $since));
	}

	private function mail(IUser $user, StepUpState $state, #[\SensitiveParameter] string $code): MailContent {
		$l = $this->messages->l10nFor($user);
		$valid = TextRenderer::duration(self::TTL, $l);
		$paragraphs = [
			$l->t('Someone just logged in to your account %s with your password, and Nextcloud needs to confirm that it is you. Enter this code on the confirmation page.', [$user->getUID()]),
			$l->t('The code is valid for %s.', [$valid]),
		];
		if ($state->ip !== null) {
			$paragraphs[] = $l->t('The login came from the address %s.', [$state->ip]);
		}
		return new MailContent(
			templateId: 'intrusion_detection.stepUpCode',
			subject: $l->t('Confirm your login'),
			heading: $l->t('Your confirmation code: %s', [$code]),
			paragraphs: $paragraphs,
			language: $l->getLanguageCode(),
			closing: [
				$l->t('If this was not you, do not enter the code anywhere. Someone knows your password: change it as soon as you can, and tell your administrator.'),
				$l->t('Nobody from Nextcloud or your administrators will ever ask you for this code.'),
			],
		);
	}
}
