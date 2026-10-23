<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OC\Core\Controller\LoginController;
use OC\Core\Controller\TwoFactorChallengeController;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IURLGenerator;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * While a login waits for its extra confirmation (concept section 11.5),
 * the session can reach nothing but the verify page, logging out, core's
 * second-factor pages and public read-only resources such as styles.
 * Browsers are sent to the verify page; other requests get 403 with
 * `{"error": "step_up_required"}`, WebDAV requests 403 with
 * `X-Nextcloud-Step-Up: required`.
 *
 * - A login that is not confirmed within {@see StepUpService::SESSION_TTL} is failed
 *   here, on its next request: the session ends.
 * - A refused login can only open the verify page, which says why and ends it.
 * - A refused app login (Basic auth) is refused for every request.
 * - A session that an app sending the password opened while a reason
 *   applied, and that was let in unconfirmed, serves apps only: WebDAV and
 *   OCS. Core gives such a login a browser session when it sends core's
 *   cookie test, and that session must not render pages the login form
 *   would have asked a confirmation for.
 * - A session whose unconfirmed login came back without its state is ended.
 *
 * With nothing pending this costs one lookup in the session; services are
 * loaded only when something is pending. Detections recorded at login are
 * linked to the session here, on its first request. Unlike other rules,
 * this one does not fail open: errors while ending a login keep the
 * request blocked, and so does {@see SessionStateRules} when the rule
 * fails while a step-up is pending.
 */
class StepUpRule implements ISessionStateRule {
	public const ERROR = 'step_up_required';
	public const ERROR_REFUSED = 'login_refused';
	public const DAV_HEADER = 'X-Nextcloud-Step-Up';
	public const ROUTE = Application::APP_ID . '.Verify.show';
	public const ENDED_ROUTE = Application::APP_ID . '.Verify.ended';

	public const MESSAGE_CLIENT = 'This login needs extra confirmation that apps cannot give. Log in with a browser, or use an app password.';
	public const MESSAGE_PENDING = 'This login waits for its extra confirmation. Confirm it in the browser where you logged in, or use an app password.';
	public const MESSAGE_REFUSED = 'This login was refused: it needs extra confirmation, and nothing could confirm it. Contact your administrator.';
	public const MESSAGE_ENDED = 'This login was ended because it was not confirmed. Log in again.';
	public const ERROR_CLIENT_ONLY = 'app_session';
	public const MESSAGE_CLIENT_ONLY = 'This session was opened by an app with the account\'s password and serves apps only. Log in with a browser.';

	public function __construct(
		private readonly IUserSession $userSession,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		$all = $state->all();
		if (($all[SessionState::CONFIRMATION][LoginConfirmation::CLIENT_ONLY] ?? false) === true
			&& !$target->dav && !$target->isController(OCSController::class)
			&& !$target->isController(LoginController::class, 'logout') && !$target->isPublicResource()) {
			return new SessionBlock(self::ERROR_CLIENT_ONLY, self::DAV_HEADER, self::MESSAGE_CLIENT_ONLY);
		}
		if (!isset($all[SessionState::STEP_UP]) && !isset($all[SessionState::LOGIN_DETECTIONS])) {
			return null;
		}
		$waiting = $state->get(SessionState::LOGIN_DETECTIONS);
		if ($waiting !== null) {
			try {
				$this->container->get(LoginDetections::class)->link($waiting, $this->userSession->getUser()?->getUID());
			} catch (\Throwable $e) {
				// Linking only helps "Was this you?" later; it must never let a pending login through.
				$this->logger->error('Intrusion detection could not link the detections of a login to its session', ['exception' => $e]);
			}
		}
		$data = $state->get(SessionState::STEP_UP);
		if ($data === null) {
			return null;
		}
		$stepUp = StepUpState::fromArray($data);
		if ($stepUp === null || $stepUp->uid !== $this->userSession->getUser()?->getUID()) {
			$state->remove(SessionState::STEP_UP);
			return null;
		}

		if ($stepUp->status === StepUpState::RESUMED
			|| ($stepUp->isPending() && $this->timeFactory->getTime() >= $stepUp->deadline)) {
			$rule = $stepUp->status === StepUpState::RESUMED ? StepUpFailed::RULE_RESUMED : StepUpFailed::RULE_TIMEOUT;
			try {
				$this->container->get(StepUpService::class)->fail($stepUp, $rule);
			} catch (\Throwable $e) {
				// The request stays blocked: an error must not turn an unconfirmed login into a confirmed one.
				$this->logger->error('Intrusion detection could not end an unconfirmed login', ['exception' => $e]);
			}
			return $this->block(self::ERROR, $this->urlGenerator->linkToRoute(self::ENDED_ROUTE, ['reason' => $rule]), self::MESSAGE_ENDED);
		}
		if ($stepUp->status === StepUpState::REFUSED_CLIENT) {
			return $this->block(self::ERROR, null, self::MESSAGE_CLIENT);
		}
		if (!$target->dav && $this->isExempt($stepUp, $target)) {
			return null;
		}
		$refused = $stepUp->status === StepUpState::REFUSED;
		return $this->block(
			$refused ? self::ERROR_REFUSED : self::ERROR,
			$this->urlGenerator->linkToRoute(self::ROUTE, ['redirect_url' => $target->uri]),
			$refused ? self::MESSAGE_REFUSED : self::MESSAGE_PENDING,
		);
	}

	/**
	 * The block while the rule itself fails and a step-up is pending: the
	 * request must not pass unconfirmed.
	 */
	public static function failed(): SessionBlock {
		return new SessionBlock(self::ERROR, self::DAV_HEADER, self::MESSAGE_PENDING);
	}

	private function isExempt(StepUpState $stepUp, RequestTarget $target): bool {
		if ($target->isController(LoginController::class, 'logout') || $target->isPublicResource()) {
			return true;
		}
		if ($stepUp->status === StepUpState::REFUSED) {
			return $target->isController(VerifyController::class, 'show');
		}
		return $target->isController(VerifyController::class)
			|| $target->isController(TwoFactorChallengeController::class)
			|| ($target->isController(ALoginSetupController::class) && $this->mustSetUpSecondFactor());
	}

	/**
	 * A provider's setup page, only while core holds the login there: at any
	 * other time a pending login could add its own second factor.
	 */
	private function mustSetUpSecondFactor(): bool {
		$user = $this->userSession->getUser();
		return $user !== null && $this->container->get(SecondFactorSetup::class)->isRequired($user);
	}

	private function block(string $error, ?string $redirectUrl, string $message): SessionBlock {
		return new SessionBlock($error, self::DAV_HEADER, $message, $redirectUrl);
	}
}
