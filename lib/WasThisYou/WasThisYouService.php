<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\UserDenied;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\SessionKiller;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\ISession;
use OCP\IUser;
use OCP\Notification\IManager as INotificationManager;

/**
 * The answers to "Was this you?" (concept section 11.8). Only ever about
 * the answering user's own detections, one answer per detection.
 *
 * - "No, it was not me" needs no confirmation: whoever clicks it can only
 *   lock out the other party. It ends the sessions and app passwords linked
 *   to the detection, requires a new password when the password was
 *   involved, blocks the address at the second level (unless the answer
 *   comes from that address), marks its network, and tells the
 *   administrators (detection `user_denied`, high).
 * - "Yes, it was me" (the controller asks for the password first) is
 *   refused from the session the detection is about, and from sessions
 *   whose own login was not confirmed: an attacker in the account must not
 *   vouch for themselves. It trusts the detection's network for the user.
 *
 * Both are audited and dispatch {@see WasThisYouAnsweredEvent}.
 */
class WasThisYouService {
	/** "No" blocks the address at this escalation level */
	public const BAN_LEVEL = 2;

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly Questions $questions,
		private readonly ResponseEngine $engine,
		private readonly UserDenied $deniedCheck,
		private readonly Settings $settings,
		private readonly FlaggedSources $flags,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly SessionKiller $sessionKiller,
		private readonly CurrentSession $currentSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly SessionState $state,
		private readonly ISession $session,
		private readonly INotificationManager $notifications,
		private readonly IEventDispatcher $dispatcher,
		private readonly AuditLogger $audit,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @throws AnswerException
	 */
	public function deny(IUser $user, int $detectionId): Detection {
		$detection = $this->ownOpen($user, $detectionId);
		$this->claim($detection, $user, Detection::VERDICT_DENIED);
		$uid = $user->getUID();
		$source = $detection->getIp() === null ? null : SourceKey::tryFromIp($detection->getIp());
		$current = $this->addresses->current();
		$sessions = Questions::sessionTokens($detection);
		$tokenId = Questions::tokenId($detection);

		$denial = null;
		$mode = $this->settings->configuredMode(UserDenied::ID);
		if ($this->settings->isEnabled() && $mode !== Mode::Off) {
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
					'network' => $source?->netKey,
					'sessionTokenIds' => $sessions,
					'tokenId' => $tokenId,
				],
				banLevel: self::BAN_LEVEL,
				sessionTokenId: $sessions[0] ?? null,
				tokenId: $tokenId,
			);
			// The account holder's own decision: learning mode does not hold it back.
			$denial = $this->engine->handle(
				$draft,
				$this->deniedCheck->responsesFor($draft, $this->settings->responses(UserDenied::ID), []),
				new ModeState($mode, $mode),
			);
			if ($mode->acts()) {
				foreach (array_slice($sessions, 1) as $sessionTokenId) {
					$this->sessionKiller->kill($uid, $sessionTokenId, null, $denial?->getId());
				}
			}
			if ($source !== null && $mode->acts()) {
				$this->flags->flagNetwork($source, FlaggedSources::REASON_USER_DENIED, $denial?->getId());
			}
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
		$source = $detection->getIp() === null ? null : SourceKey::tryFromIp($detection->getIp());
		if ($source !== null) {
			$this->trustedNetworks->trust($user->getUID(), $source, $detection->getId());
		}
		$this->finish($detection, $user, Detection::VERDICT_CONFIRMED);
		$this->audit->log('%s answered "Yes, it was me" about detection %s (%s)', ['uid' => $user->getUID(), 'detection' => $detection->getId(), 'check' => $detection->getCheckId()]);
		return $detection;
	}

	/**
	 * Whether the current session may say "Yes, it was me" about the
	 * detection: not the session (or app password) it is about, not an app
	 * password session, and not a session whose own login was not confirmed.
	 */
	public function maySessionVouch(Detection $detection): bool {
		$current = $this->currentSession->tokenId();
		if ($current === null || $this->session->exists('app_password')) {
			return false;
		}
		if (in_array($current, Questions::sessionTokens($detection), true) || $current === Questions::tokenId($detection)) {
			return false;
		}
		$confirmation = $this->state->get(SessionState::CONFIRMATION);
		return ($confirmation['by'] ?? null) !== StepUpService::CONFIRMED_BY_NONE
			&& $this->state->get(SessionState::STEP_UP) === null;
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
