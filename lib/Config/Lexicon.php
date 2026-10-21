<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCP\Config\Lexicon\Entry;
use OCP\Config\Lexicon\ILexicon;
use OCP\Config\Lexicon\Strictness;
use OCP\Config\ValueType;

/**
 * Every config key of the app, from {@see LexiconData}: the global settings
 * and the check registry compiled into static data. Core asks for it on the
 * first app config read of every request, so it builds no check and no
 * setting definition and has no dependencies.
 */
final class Lexicon implements ILexicon {

	#[\Override]
	public function getStrictness(): Strictness {
		return Strictness::NOTICE;
	}

	#[\Override]
	public function getAppConfigs(): array {
		$entries = [];
		foreach (LexiconData::GLOBALS as $name => $spec) {
			$entries[] = new Entry($name, ParamType::from($spec['type'])->valueType(), $spec['default'], 'intrusion detection: ' . $name);
		}
		foreach (LexiconData::CHECKS as $id => $check) {
			$entries[] = new Entry(Keys::mode($id), ValueType::STRING, $check['mode'], 'mode of the ' . $id . ' check');
			$entries[] = new Entry(Keys::responses($id), ValueType::ARRAY, $check['responses'], 'responses of the ' . $id . ' check');
			foreach ($check['params'] as $name => $spec) {
				$entries[] = new Entry(Keys::param($id, $name), ParamType::from($spec['type'])->valueType(), $spec['default'], $id . ' check: ' . $name);
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
			new Entry(UntrustedSecondFactors::USER_KEY, ValueType::ARRAY, [], 'second factors set up from a session whose login was not confirmed: provider id => when'),
			new Entry(SecureAccountGuide::USER_KEY, ValueType::STRING, '', 'progress through the "Secure my account" checklist (JSON)', lazy: true),
		];
	}
}
