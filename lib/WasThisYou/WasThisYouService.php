<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDenied;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\SessionKiller;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUser;
use OCP\Notification\IManager as INotificationManager;

/**
 * The answers to "Was this you?" (concept section 11.8). Only ever about
 * the answering user's own detections, one answer per detection. Neither
 * answer is taken from a session whose own login is unconfirmed
 * ({@see SessionConfirmation}).
 *
 * - "No, it was not me" ends the sessions and app passwords linked to the
 *   detection, requires a new password when the password was involved,
 *   blocks the address at the second level (unless the answer comes from
 *   that address), marks its network, and tells the administrators
 *   (detection `user_denied`, high). From a session whose login proved no
 *   more than the password, or with an app password (the Nextcloud apps
 *   answer the notification with theirs), which an attacker could have
 *   too, the administrators are told, but nothing else is done: the
 *   question stays open, with its notification, until a session that
 *   proved more answers it. Such a "No" never claims the answer, so it
 *   cannot silence the account holder, and it keeps the remembered
 *   devices. Only the first one per detection is recorded; later ones
 *   change nothing.
 * - "Yes, it was me" (the controller asks for the password first) needs a
 *   browser session whose login proved more than the password, and not
 *   the session the detection is about: an attacker in the account must
 *   not vouch for themselves. It trusts the detection's network for the
 *   user.
 *
 * Detections that involve two addresses ({@see Questions::TWO_SOURCES})
 * never block, mark or trust a network on an answer.
 *
 * Both are audited, and both answers that close the question dispatch
 * {@see WasThisYouAnsweredEvent}.
 */
class WasThisYouService {
	/** "No" blocks the address at this escalation level */
	public const BAN_LEVEL = 2;

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly Questions $questions,
		private readonly ResponseEngine $engine,
		private readonly AppSettings $appSettings,
		private readonly CheckSettings $settings,
		private readonly FlaggedSources $flags,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly SessionKiller $sessionKiller,
		private readonly CurrentSession $currentSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly SessionConfirmation $confirmation,
		private readonly INotificationManager $notifications,
		private readonly IEventDispatcher $dispatcher,
		private readonly AuditLogger $audit,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return Detection the detection; still without an answer when the session proved only the password
	 * @throws AnswerException
	 */
	public function deny(IUser $user, int $detectionId): Detection {
		$detection = $this->ownOpen($user, $detectionId);
		$uid = $user->getUID();
		$level = $this->confirmation->denialLevel($uid);
		if ($level === SessionConfirmation::UNCONFIRMED) {
			throw new AnswerException(AnswerException::SESSION_NOT_ALLOWED);
		}
		$weak = $level !== SessionConfirmation::PROVEN;
		if (!$weak) {
			$this->claim($detection, $user, Detection::VERDICT_DENIED);
		}
		$source = Questions::answerSource($detection);
		$current = $this->addresses->current();
		$sessions = Questions::sessionTokens($detection);
		$tokenId = Questions::tokenId($detection);

		$denial = null;
		$mode = $this->settings->configuredMode(UserDenied::ID);
		if ($this->appSettings->isEnabled() && $mode !== Mode::Off) {
			$draft = new DetectionDraft(
				checkId: UserDenied::ID,
				source: $source,
				uid: $uid,
				facts: [
					'detection' => $detection->getId(),
					'check' => $detection->getCheckId(),
					'detectedAt' => $detection->getCreatedAt(),
					'passwordInvolved' => $this->questions->involvesPassword($detection),
					'answeredFromSource' => $source !== null && $current !== null && $source->ipKey === $current->ipKey,
					'network' => $weak ? null : $source?->netKey,
					'weakSession' => $weak,
					'sessionTokenIds' => $sessions,
					'tokenId' => $tokenId,
				],
				merge: $weak ? DetectionDraft::MERGE_SUBJECT : DetectionDraft::MERGE_NONE,
				mergeWindow: $this->appSettings->retentionDays() * 86400,
				banLevel: self::BAN_LEVEL,
				sessionTokenId: $sessions[0] ?? null,
				tokenId: $tokenId,
				// The account holder's own decision: learning mode does not hold it back.
				mode: new ModeState($mode, $mode),
			);
			if ($weak && $this->weaklyDenied($draft)) {
				$this->audit->log('%s answered "No, it was not me" about detection %s again from a session that proved only the password; nothing was recorded', ['uid' => $uid, 'detection' => $detection->getId()]);
				return $detection;
			}
			// A weak "No" at the same time as another is merged into it.
			$denial = $this->engine->handle($draft);
			if ($mode->acts() && !$weak) {
				foreach (array_slice($sessions, 1) as $sessionTokenId) {
					$this->sessionKiller->kill($uid, $sessionTokenId, null, $denial?->getId());
				}
				if ($source !== null) {
					$this->flags->flagNetwork($source, FlaggedSources::REASON_USER_DENIED, $denial?->getId());
				}
			}
		}
		if ($weak) {
			$this->audit->log('%s answered "No, it was not me" about detection %s (%s) from a session that proved only the password; the question stays open', ['uid' => $uid, 'detection' => $detection->getId(), 'check' => $detection->getCheckId()]);
			return $detection;
		}
		if ($source !== null) {
			$this->trustedNetworks->distrust($uid, $source);
		}
		$this->finish($detection, $user, Detection::VERDICT_DENIED);
		$this->audit->log('%s answered "No, it was not me" about detection %s (%s)', ['uid' => $uid, 'detection' => $detection->getId(), 'check' => $detection->getCheckId()]);
		return $detection;
	}

	/**
	 * @throws AnswerException
	 */
	public function confirm(IUser $user, int $detectionId): Detection {
		$detection = $this->ownOpen($user, $detectionId);
		if (!$this->maySessionVouch($detection)) {
			throw new AnswerException(AnswerException::SESSION_NOT_ALLOWED);
		}
		$this->claim($detection, $user, Detection::VERDICT_CONFIRMED);
		$source = Questions::answerSource($detection);
		if ($source !== null) {
			$this->trustedNetworks->trust($user->getUID(), $source, $detection->getId());
		}
		$this->finish($detection, $user, Detection::VERDICT_CONFIRMED);
		$this->audit->log('%s answered "Yes, it was me" about detection %s (%s)', ['uid' => $user->getUID(), 'detection' => $detection->getId(), 'check' => $detection->getCheckId()]);
		return $detection;
	}

	/**
	 * Whether the current session may say "Yes, it was me" about the
	 * detection: its login proved more than the password, and it is not the
	 * session (or app password) the detection is about.
	 */
	public function maySessionVouch(Detection $detection): bool {
		$current = $this->currentSession->tokenId();
		if ($current === null || $detection->getUid() === null || !$this->confirmation->isProven($detection->getUid())) {
			return false;
		}
		return !in_array($current, Questions::sessionTokens($detection), true) && $current !== Questions::tokenId($detection);
	}

	/**
	 * Whether a weak "No" about the same detection was recorded already.
	 */
	private function weaklyDenied(DetectionDraft $draft): bool {
		$key = $draft->mergeKey();
		return $key !== null && $this->detections->findMergeable($key, $this->timeFactory->getTime() - $draft->mergeWindow) !== null;
	}

	/**
	 * @throws AnswerException
	 */
	private function ownOpen(IUser $user, int $detectionId): Detection {
		try {
			$detection = $this->detections->findById($detectionId);
		} catch (DoesNotExistException) {
			throw new AnswerException(AnswerException::NOT_FOUND);
		}
		if ($detection->getUid() !== $user->getUID()) {
			// Other accounts' detections are indistinguishable from missing ones.
			throw new AnswerException(AnswerException::NOT_FOUND);
		}
		if (!$this->questions->asks($detection)) {
			throw new AnswerException(AnswerException::NOT_ASKED);
		}
		if ($detection->getUserVerdict() !== null) {
			throw new AnswerException(AnswerException::ANSWERED);
		}
		return $detection;
	}

	/**
	 * @param Detection::VERDICT_* $verdict
	 * @throws AnswerException
	 */
	private function claim(Detection $detection, IUser $user, string $verdict): void {
		$now = $this->timeFactory->getTime();
		if (!$this->detections->setVerdict($detection->getId(), $user->getUID(), $verdict, $now)) {
			throw new AnswerException(AnswerException::ANSWERED);
		}
		$detection->setUserVerdict($verdict);
		$detection->setVerdictAt($now);
		$detection->resetUpdatedFields();
	}

	/**
	 * @param Detection::VERDICT_* $verdict
	 */
	private function finish(Detection $detection, IUser $user, string $verdict): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($user->getUID())
			->setObject(UserAlerts::OBJECT_TYPE, (string)$detection->getId());
		$this->notifications->markProcessed($notification);
		$this->dispatcher->dispatchTyped(new WasThisYouAnsweredEvent($detection, $verdict));
	}
}
