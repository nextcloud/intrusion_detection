<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\CoreHooks;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;

/**
 * Nextcloud server lacks APIs the app hooks into ({@see CoreHooks}): the
 * parts of the app that use them do nothing, which must not look like
 * protection.
 */
class CoreHooksCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly CoreHooks $hooks,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: server support');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Nextcloud server offers everything intrusion detection hooks into.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$missing = $this->hooks->missing();
		if ($missing === []) {
			return null;
		}
		return new Finding(
			'core_hooks_missing',
			Finding::LEVEL_ERROR,
			$l->t('This Nextcloud server lacks what intrusion detection needs'),
			$l->t('Missing: %s.', [implode(', ', array_map(fn (string $hook): string => $this->describe($hook, $l), $missing))]) . ' ' . $l->t('The parts of intrusion detection that use them do nothing, and the checks that need them cannot be switched on.'),
			$l->t('Update Nextcloud server to the version this app is made for.'),
		);
	}

	private function describe(string $hook, IL10N $l): string {
		return match ($hook) {
			CoreHooks::REQUEST_GUARDS => $l->t('checking every request, so blocks, blocklists, trap URLs and injection probes are not enforced'),
			CoreHooks::SHARE_ACCESS_EVENT => $l->t('failed share link accesses'),
			CoreHooks::RESET_EVENT => $l->t('password reset requests'),
			CoreHooks::LOGIN_FLOW_EVENT => $l->t('logins granted to apps and clients'),
			CoreHooks::APP_PASSWORD_EVENT => $l->t('new app passwords'),
			CoreHooks::CHALLENGE_REQUESTER => $l->t('asking for a second factor to confirm a login'),
			CoreHooks::DAV_PLUGIN_EVENT => $l->t('holding WebDAV requests of unconfirmed logins'),
			default => $hook,
		};
	}
}
