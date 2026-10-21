<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\IGroup;
use OCP\IUser;

/**
 * Decides whether an account just added to the admin group must wait for the
 * approval of a second administrator (concept section 10.15).
 *
 * Core cannot veto an addition (BeforeUserAddedEvent has no way to stop it),
 * so an addition that needs approval is taken back at once and turned into
 * a request. Exempt, and only reported:
 *
 * - occ and background jobs on the command line: whoever can start them
 *   already controls the server;
 * - groups that a user directory (LDAP or another backend than Nextcloud's
 *   own database) provides: Nextcloud cannot undo what the directory sets,
 *   and the next sync would add the member again.
 *
 * Approval applies while the setting is on and the check is set to Protect,
 * also during learning mode: an administrator switched it on deliberately.
 */
class AdminGrantGate {
	public const NOT_NEEDED = 'not_needed';
	/** A second administrator approved this very addition */
	public const APPROVED = 'approved';
	public const NEEDS_APPROVAL = 'needs_approval';

	/** The name core's own group backend reports */
	public const DATABASE_BACKEND = 'Database';

	/** @var array<string, scalar>|null the facts of the permit used by the last decide() */
	private ?array $permitFacts = null;

	public function __construct(
		private readonly Settings $settings,
		private readonly ActorResolver $actors,
		private readonly GrantPermit $permit,
	) {
	}

	/**
	 * @return string one of the constants, or one of the AdminChange::EXEMPT_* reasons
	 */
	public function decide(IGroup $group, IUser $user): string {
		$this->permitFacts = $this->permit->consume($user->getUID(), $group->getGID());
		if ($this->permitFacts !== null) {
			return self::APPROVED;
		}
		if ($group->getGID() !== Approvers::ADMIN_GROUP || !$this->isRequired()) {
			return self::NOT_NEEDED;
		}
		if ($this->isDirectoryBacked($group)) {
			return AdminChange::EXEMPT_DIRECTORY;
		}
		if ($this->actors->isConsole()) {
			return AdminChange::EXEMPT_OCC;
		}
		if ($this->actors->isCommandLine()) {
			return AdminChange::EXEMPT_CRON;
		}
		return self::NEEDS_APPROVAL;
	}

	/**
	 * @return array<string, scalar> what the approval that let the last addition through recorded
	 */
	public function permitFacts(): array {
		return $this->permitFacts ?? [];
	}

	public function isRequired(): bool {
		return $this->settings->getBool(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL)
			&& $this->settings->isEnabled()
			&& $this->settings->configuredMode(AdminChange::ID) === Mode::Protect;
	}

	/**
	 * Whether a backend other than Nextcloud's own database provides the group.
	 */
	public function isDirectoryBacked(IGroup $group): bool {
		foreach ($group->getBackendNames() as $name) {
			if ($name !== self::DATABASE_BACKEND) {
				return true;
			}
		}
		return false;
	}
}
