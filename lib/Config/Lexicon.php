<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCP\Config\Lexicon\Entry;
use OCP\Config\Lexicon\ILexicon;
use OCP\Config\Lexicon\Strictness;
use OCP\Config\ValueType;

/**
 * Every config key of the app, generated from the global settings and the
 * check registry, so that the two cannot drift apart.
 */
final class Lexicon implements ILexicon {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly GlobalSettings $globals,
	) {
	}

	#[\Override]
	public function getStrictness(): Strictness {
		return Strictness::NOTICE;
	}

	#[\Override]
	public function getAppConfigs(): array {
		$entries = [];
		foreach ($this->globals->all() as $definition) {
			$entries[] = new Entry($definition->name, $definition->type->valueType(), $definition->default, 'intrusion detection: ' . $definition->name);
		}
		foreach ($this->registry->all() as $check) {
			$entries[] = new Entry(Keys::mode($check->id), ValueType::STRING, $check->defaultMode->value, 'mode of the ' . $check->id . ' check');
			$entries[] = new Entry(
				Keys::responses($check->id),
				ValueType::ARRAY,
				array_map(static fn (ResponseType $r): string => $r->value, $check->defaultResponses),
				'responses of the ' . $check->id . ' check',
			);
			foreach ($check->params as $param) {
				$entries[] = new Entry(Keys::param($check->id, $param->name), $param->type->valueType(), $param->default, $check->id . ' check: ' . $param->name);
			}
		}
		return $entries;
	}

	#[\Override]
	public function getUserConfigs(): array {
		return [
			new Entry(BreachedPasswordDetector::KEY_CHECKED_AT, ValueType::INT, 0, 'when the password was last checked against the breach list', lazy: true),
			new Entry(BreachedPasswordDetector::KEY_BREACHED, ValueType::BOOL, false, 'the current password was found on the breach list', lazy: true),
			new Entry(PasswordChangeFlag::USER_KEY, ValueType::INT, 0, 'when a new password was required at the next login (0: not required)'),
			new Entry(LoginNotices::USER_KEY, ValueType::INT, 0, 'when the oldest security event happened that the user could only be told inside Nextcloud and has not seen at a login yet (0: none)'),
			new Entry(SecureAccountGuide::USER_KEY, ValueType::STRING, '', 'progress through the "Secure my account" checklist (JSON)', lazy: true),
		];
	}
}
