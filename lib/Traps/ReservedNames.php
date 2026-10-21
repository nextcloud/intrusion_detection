<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Config\Settings;

/**
 * The reserved login names of the `reserved_name` check.
 *
 * Names are compared lower-cased and trimmed. A name that is an existing
 * account cannot be reserved. Accounts can still appear later (LDAP, SAML);
 * such names are skipped at login and listed by {@see self::collisions()}.
 * Core offers no reliable veto on account creation: BeforeUserCreatedEvent
 * only covers accounts created through the user manager, never accounts that
 * a directory backend provides.
 */
class ReservedNames {
	/** Offered on first setup; only those that are not accounts are suggested */
	public const SUGGESTIONS = ['admin', 'administrator', 'root', 'nextcloud', 'owncloud', 'test', 'user', 'guest', 'support', 'webmaster'];
	public const NAME_PATTERN = '/^[^\s\x00-\x1f\x7f]{1,64}$/u';
	public const MAX_NAMES = 100;

	public function __construct(
		private readonly Settings $settings,
		private readonly AccountNames $accounts,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @return list<string>
	 */
	public function list(): array {
		return $this->settings->paramList(ReservedName::ID, 'names');
	}

	/**
	 * The suggested names that are neither reserved yet nor accounts.
	 *
	 * @return list<string>
	 */
	public function suggestions(): array {
		$reserved = $this->list();
		return array_values(array_filter(
			self::SUGGESTIONS,
			fn (string $name): bool => !in_array($name, $reserved, true) && !$this->accounts->exists($name),
		));
	}

	/**
	 * @param list<string> $names
	 * @return list<string> the reserved names afterwards
	 * @throws InvalidParamException when a name is invalid or an existing account
	 */
	public function add(array $names, string $actor): array {
		$list = array_values(array_unique(array_merge($this->list(), array_map(AccountNames::normalise(...), $names))));
		$this->settings->setParam(ReservedName::ID, 'names', $list);
		$this->audit->log('reserved names %s added by %s', ['names' => implode(', ', $names), 'actor' => $actor]);
		return $this->list();
	}

	/**
	 * @param list<string> $names
	 * @return list<string> the reserved names afterwards
	 */
	public function remove(array $names, string $actor): array {
		$remove = array_map(AccountNames::normalise(...), $names);
		$list = array_values(array_filter($this->list(), static fn (string $n): bool => !in_array($n, $remove, true)));
		$this->settings->setParam(ReservedName::ID, 'names', $list);
		$this->audit->log('reserved names %s removed by %s', ['names' => implode(', ', $names), 'actor' => $actor]);
		return $this->list();
	}

	/**
	 * The reserved name a login name matches, unless an account with that
	 * name exists by now.
	 */
	public function match(string $loginName): ?string {
		$reserved = $this->list();
		if ($reserved === []) {
			return null;
		}
		$name = AccountNames::normalise($loginName);
		if (!in_array($name, $reserved, true) || $this->accounts->exists($name)) {
			return null;
		}
		return $name;
	}

	/**
	 * Reserved names that have become accounts since they were reserved.
	 *
	 * @return list<string>
	 */
	public function collisions(): array {
		return array_values(array_filter($this->list(), fn (string $name): bool => $this->accounts->exists($name)));
	}
}
