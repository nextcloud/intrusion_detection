<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCP\Config\Lexicon\Entry;
use OCP\Config\Lexicon\ILexicon;
use OCP\Config\Lexicon\Strictness;
use OCP\Config\ValueType;

/**
 * Every config key of the app, from {@see LexiconData}: the global settings
 * and the check registry compiled into static data, value types included.
 * Core asks for it on the first app config read of every request, so it
 * builds no check and no setting definition, has no dependencies and only
 * creates the entry objects core wants.
 */
final class Lexicon implements ILexicon {

	#[\Override]
	public function getStrictness(): Strictness {
		return Strictness::NOTICE;
	}

	#[\Override]
	public function getAppConfigs(): array {
		$entries = [];
		foreach (LexiconData::ENTRIES as [$key, $type, $default, $definition]) {
			$entries[] = new Entry($key, $type, $default, $definition);
		}
		return $entries;
	}

	#[\Override]
	public function getUserConfigs(): array {
		return [
			new Entry(UserKeys::BREACH_CHECKED_AT, ValueType::INT, 0, 'when the password was last checked against the breach list', lazy: true),
			new Entry(UserKeys::BREACHED, ValueType::BOOL, false, 'the current password was found on the breach list', lazy: true),
			new Entry(UserKeys::FORCE_PASSWORD_CHANGE, ValueType::INT, 0, 'when a new password was required at the next login (0: not required)'),
			new Entry(UserKeys::LOGIN_NOTICE_SINCE, ValueType::INT, 0, 'when the oldest security event happened that the user could only be told inside Nextcloud and has not seen at a login yet (0: none)'),
			new Entry(UserKeys::UNTRUSTED_SECOND_FACTORS, ValueType::ARRAY, [], 'second factors set up from a session whose login proved only the password: provider id => when, or when and until when'),
			new Entry(UserKeys::CODE_MAILS, ValueType::ARRAY, [], 'when the last confirmation codes were sent to the account, to limit them per hour', lazy: true),
			new Entry(UserKeys::CODE_WRONG, ValueType::ARRAY, [], 'when wrong confirmation codes were entered for the account, to limit them per hour', lazy: true),
			new Entry(UserKeys::SECURE_GUIDE, ValueType::STRING, '', 'progress through the "Secure my account" checklist (JSON)', lazy: true),
			new Entry(UserKeys::STALE_CREDENTIALS_NOTIFIED_AT, ValueType::INT, 0, 'when the user was last reminded of app passwords and devices they have not used for 90 days (0: never)', lazy: true),
			new Entry(UserKeys::LEARNING_RECAP_CLOSED, ValueType::INT, 0, 'when the learning period ended whose recap on the overview the administrator closed (0: none)', lazy: true),
		];
	}
}
