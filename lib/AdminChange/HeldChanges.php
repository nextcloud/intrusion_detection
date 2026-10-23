<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;

/**
 * The settings changes that would switch the four-eyes approval of new
 * administrators off. While it is on, such a change from the admin page or
 * the API waits for the approval of a second administrator
 * ({@see ApprovalService::hold()}), and is made when one approves. occ is
 * not held: whoever can run it controls the server, and the change is
 * reported like every other.
 *
 * The approval ends when the master switch, the approval setting or the
 * Protect mode of the admin change check ends ({@see AdminGrantGate::isRequired()}).
 * With the config.php lock, nothing that would end it can be changed at
 * all, so nothing is held. A change is held whole, with every other value it carries, so that it is
 * made as asked or not at all. It is one of:
 *
 * - `settings`: global settings, `values` by name as validated;
 * - `check`: the mode, responses and settings of a check, as given;
 * - `reset_check`: a check back to its defaults;
 * - `reset_all`: every setting back to its default.
 *
 * @psalm-import-type HeldChange from Approval
 */
class HeldChanges {
	public const SETTINGS = 'settings';
	public const CHECK = 'check';
	public const RESET_CHECK = 'reset_check';
	public const RESET_ALL = 'reset_all';

	public function __construct(
		private readonly AdminGrantGate $gate,
		private readonly GlobalSettings $globals,
		private readonly CheckRegistry $registry,
		private readonly SettingsEditor $editor,
		private readonly AppSettings $appSettings,
	) {
	}

	/**
	 * Whether the change waits for a second administrator.
	 *
	 * @param HeldChange $change
	 */
	public function needsApproval(array $change): bool {
		return $this->gate->isRequired() && !$this->appSettings->isLocked() && $this->endsApproval($change);
	}

	/**
	 * Make a change a second administrator approved. Its values are
	 * validated again, against the definitions of now.
	 *
	 * @param HeldChange $change
	 * @throws InvalidParamException
	 */
	public function apply(array $change, string $actor): void {
		match ($change['op']) {
			self::SETTINGS => $this->editor->updateGlobals($change['values'] ?? []),
			self::CHECK => $this->editor->changeCheck((string)($change['check'] ?? ''), $change['mode'] ?? null, $change['responses'] ?? null, $change['params'] ?? [], $actor),
			self::RESET_CHECK => $this->editor->resetCheck((string)($change['check'] ?? ''), $actor),
			self::RESET_ALL => $this->editor->resetAll(),
			default => throw new InvalidParamException('unknown_param', ['param' => 'op']),
		};
	}

	/**
	 * @param HeldChange $change
	 */
	private function endsApproval(array $change): bool {
		$check = (string)($change['check'] ?? '');
		return match ($change['op']) {
			self::SETTINGS => $this->switchesOff($change['values'] ?? []),
			self::CHECK => $check === AdminChange::ID && isset($change['mode']) && $change['mode'] !== Mode::Protect->value,
			self::RESET_CHECK => $check === AdminChange::ID && $this->registry->get(AdminChange::ID)->defaultMode !== Mode::Protect,
			self::RESET_ALL => $this->switchesOff([
				GlobalSettings::ENABLED => $this->globals->get(GlobalSettings::ENABLED)?->default,
				GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => $this->globals->get(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL)?->default,
			]) || $this->registry->get(AdminChange::ID)->defaultMode !== Mode::Protect,
			default => false,
		};
	}

	/**
	 * @param array<string, mixed> $values
	 */
	private function switchesOff(array $values): bool {
		foreach ([GlobalSettings::ENABLED, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL] as $name) {
			if (array_key_exists($name, $values) && $values[$name] !== true) {
				return true;
			}
		}
		return false;
	}
}
