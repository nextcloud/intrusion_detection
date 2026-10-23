<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCP\IURLGenerator;
use OCP\IUserSession;

/**
 * "Administrators log in from trusted networks only" for the whole
 * session of an administrator's login ({@see SessionMarkers::ADMIN_SESSION}):
 * while the switch is on, a request from outside the trusted networks
 * ends the session, unless its login was confirmed with something the
 * rule accepts. The next login from there is a password login, which must
 * confirm. This covers a session that moves, one that came back with its
 * remember-me cookie, and trusted networks that changed since the login,
 * as the networks are read on every request.
 *
 * The rule accepts what confirms a login from outside the networks: the
 * second factor, an emailed code or an approval, and a login let in
 * without a method where the rule's own setting allows that. A remembered
 * device is no proof of the network.
 */
class AdminNetworkRule implements ISessionStateRule {
	public const ERROR = 'admin_outside_networks';
	public const MESSAGE = 'This administrator session was ended because it was used from outside the trusted networks. Log in again.';
	private const ACCEPTED = [IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE, IConfirmationMethod::ADMIN_APPROVAL];

	public function __construct(
		private readonly AppSettings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly IUserSession $userSession,
		private readonly IURLGenerator $urlGenerator,
		private readonly AuditLogger $audit,
	) {
	}

	#[\Override]
	public function check(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		$marker = $state->get(SessionMarkers::ADMIN_SESSION);
		if ($marker === null || !$this->settings->isEnabled() || !$this->settings->adminTrustedNetworksOnly()) {
			return null;
		}
		$uid = $this->userSession->getUser()?->getUID();
		if ($uid === null || ($marker['uid'] ?? null) !== $uid) {
			$state->remove(SessionMarkers::ADMIN_SESSION);
			return null;
		}
		$source = $this->addresses->current();
		if ($source !== null && RangeCodec::firstContaining($this->settings->riskyNetworkOfficeNetworks(), $source) !== null) {
			return null;
		}
		if (self::accepts(LoginConfirmation::fromMarkers($state->all(), $uid))) {
			return null;
		}
		$this->audit->log('session of administrator %s ended: used from %s, outside the trusted networks', ['uid' => $uid, 'ip' => $source?->ip ?? 'an unknown address']);
		$this->userSession->logout();
		return new SessionBlock(self::ERROR, StepUpRule::DAV_HEADER, self::MESSAGE, $this->urlGenerator->linkToRoute('core.login.showLoginForm'));
	}

	private static function accepts(LoginConfirmation $confirmation): bool {
		return match ($confirmation->status) {
			ConfirmationStatus::Confirmed, ConfirmationStatus::Proven => in_array($confirmation->method, self::ACCEPTED, true),
			ConfirmationStatus::AllowedUnconfirmed => in_array(StepUpPolicy::AdminOutsideNetworks->value, $confirmation->policies, true),
			default => false,
		};
	}
}
