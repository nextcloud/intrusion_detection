<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\Config\IUserConfig;
use OCP\IDateTimeZone;
use OCP\IL10N;
use OCP\IUser;
use OCP\L10N\IFactory;
use Psr\Container\ContainerInterface;

/**
 * Builds what the affected user is told about a detection: the check's own
 * words ({@see IExplainsToUser}), when it happened in the user's time zone,
 * the address and a short user agent, what Nextcloud did, and what to do.
 *
 * Users never see thresholds, other accounts or anything meant for the
 * administrators.
 */
class UserMessages {
	/** User agents are cut to this length */
	public const MAX_USER_AGENT = 200;
	/** At most this many blocked addresses are named */
	public const MAX_ADDRESSES = 3;

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly ContainerInterface $container,
		private readonly DateFormatter $dates,
		private readonly IFactory $l10nFactory,
		private readonly IUserConfig $userConfig,
		private readonly IDateTimeZone $dateTimeZone,
		private readonly UserLinks $links,
		private readonly Questions $questions,
	) {
	}

	/**
	 * The app's translations in the user's language and locale.
	 */
	public function l10nFor(IUser $user, ?string $language = null): IL10N {
		$locale = $this->userConfig->getValueString($user->getUID(), 'core', 'locale');
		return $this->l10nFactory->get(Application::APP_ID, $language ?? $this->l10nFactory->getUserLanguage($user), $locale !== '' ? $locale : null);
	}

	public function build(Detection $detection, IUser $user, ?string $language = null): UserMessage {
		$l = $this->l10nFor($user, $language);
		$notice = $this->notice($detection, $l);
		$advice = $notice->advice !== [] ? $notice->advice : [$l->t('If this was not you, change your password and check your devices and sessions in your security settings.')];
		if ($this->questions->isOpen($detection)) {
			$advice[] = $l->t('Was this you? Answer "Yes, it was me" or "No, it was not me" in the notification about it in Nextcloud.');
		}
		return new UserMessage(
			$notice->subject,
			$notice->message,
			$this->when($detection, $user, $l),
			$this->done($detection, $l),
			$advice,
			$l->getLanguageCode(),
		);
	}

	public function mail(Detection $detection, IUser $user): MailContent {
		$message = $this->build($detection, $user);
		$l = $this->l10nFor($user, $message->language);
		return new MailContent(
			templateId: 'intrusion_detection.userNotice',
			subject: $l->t('Security notice: %s', [$message->subject]),
			heading: $message->subject,
			paragraphs: array_merge($message->happened, [$message->when]),
			listHeading: $message->done === [] ? '' : $l->t('What Nextcloud did:'),
			listItems: $message->done,
			buttonText: $l->t('Open your security settings'),
			buttonUrl: $this->links->securityPage(),
			language: $message->language,
			closing: $message->advice,
		);
	}

	/**
	 * A user agent as users are shown it: control characters removed, cut short.
	 */
	public static function shortUserAgent(?string $userAgent): ?string {
		if ($userAgent === null) {
			return null;
		}
		$clean = trim((string)(preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $userAgent) ?? ''));
		if ($clean === '') {
			return null;
		}
		return mb_strlen($clean) > self::MAX_USER_AGENT ? mb_substr($clean, 0, self::MAX_USER_AGENT - 1) . '…' : $clean;
	}

	private function notice(Detection $detection, IL10N $l): UserNotice {
		try {
			$check = $this->container->get($this->registry->classOf($detection->getCheckId()));
		} catch (InvalidParamException) {
			$check = null;
		}
		if ($check instanceof IExplainsToUser) {
			return $check->userNotice($detection, $l);
		}
		return new UserNotice($l->t('Unusual activity on your account'), [$l->t('Nextcloud noticed unusual activity on your account.')]);
	}

	private function when(Detection $detection, IUser $user, IL10N $l): string {
		$time = $this->dates->dateTimeFor($detection->getCreatedAt(), $this->timeZone($user), $l);
		$ip = $detection->getIp();
		$userAgent = self::shortUserAgent(is_string($detection->getExplanationData()['userAgent'] ?? null) ? $detection->getExplanationData()['userAgent'] : null);
		if ($ip === null) {
			return $l->t('This happened on %s.', [$time]);
		}
		if ($userAgent === null) {
			return $l->t('This happened on %1$s, from the address %2$s.', [$time, $ip]);
		}
		return $l->t('This happened on %1$s, from the address %2$s, with "%3$s".', [$time, $ip, $userAgent]);
	}

	/**
	 * The user's own time zone setting, else the server's default. The time
	 * zone of the browser that made the request is not used: it may be the
	 * attacker's.
	 */
	private function timeZone(IUser $user): \DateTimeZone {
		$name = $this->userConfig->getValueString($user->getUID(), 'core', 'timezone');
		if ($name !== '') {
			try {
				return new \DateTimeZone($name);
			} catch (\Exception) {
				// Fall back to the default below.
			}
		}
		return $this->dateTimeZone->getDefaultTimeZone();
	}

	/**
	 * What Nextcloud did, in the user's words. Only enforced actions count.
	 *
	 * @return list<string>
	 */
	private function done(Detection $detection, IL10N $l): array {
		$sentences = [];
		foreach ($detection->getActionList() as $action) {
			if (!$action['enforced']) {
				continue;
			}
			$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
			array_push($sentences, ...match ($action['type']) {
				ResponseType::Ban->value => $this->banSentences($ref, $l),
				ResponseType::KillSession->value => $this->killSentences($ref, $l),
				ResponseType::RevokeToken->value => $this->revokeSentences($ref, $l),
				ResponseType::ForcePasswordChange->value => match ($ref['state'] ?? null) {
					PasswordChangeService::STATE_REQUIRED => [$l->t('You will be asked to choose a new password the next time you log in.')],
					PasswordChangeService::STATE_EXTERNAL => [$l->t('Your password is managed outside Nextcloud, so your administrator was asked to reset it.')],
					default => [],
				},
				ResponseType::NotifyAdmin->value => (int)($ref['recipients'] ?? 0) > 0 ? [$l->t('Your administrators were told.')] : [],
				default => [],
			});
		}
		return $sentences;
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function banSentences(array $ref, IL10N $l): array {
		$cidrs = [];
		foreach ((array)($ref['bans'] ?? []) as $ban) {
			if (is_array($ban) && is_string($ban['cidr'] ?? null)) {
				$cidrs[] = $ban['cidr'];
			}
		}
		if ($cidrs === []) {
			return [];
		}
		$cidrs = array_slice(array_values(array_unique($cidrs)), 0, self::MAX_ADDRESSES);
		return [$l->n('The address %s was blocked.', 'The addresses %s were blocked.', count($cidrs), [implode(', ', $cidrs)])];
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function killSentences(array $ref, IL10N $l): array {
		$sentences = [];
		if (is_array($ref['session'] ?? null)) {
			$sentences[] = $l->t('The suspicious session was ended.');
		}
		$tokens = count((array)($ref['tokens'] ?? []));
		if ($tokens > 0) {
			$sentences[] = $l->n(
				'%n app password that came with it was revoked.',
				'%n app passwords that came with it were revoked.',
				$tokens,
			);
		}
		return $sentences;
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function revokeSentences(array $ref, IL10N $l): array {
		$sentences = [];
		if (is_array($ref['token'] ?? null)) {
			$sentences[] = ($ref['session'] ?? false) === true
				? $l->t('The session "%s" was ended.', [(string)($ref['token']['name'] ?? '')])
				: $l->t('The app password "%s" was revoked.', [(string)($ref['token']['name'] ?? '')]);
		}
		$tokens = count((array)($ref['tokens'] ?? []));
		if ($tokens > 0) {
			$sentences[] = $l->n(
				'%n app password created with it was revoked as well.',
				'%n app passwords created with it were revoked as well.',
				$tokens,
			);
		}
		return $sentences;
	}
}
