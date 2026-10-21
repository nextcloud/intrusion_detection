<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\IL10N;

/**
 * A reserved login name or the login name of a decoy has become a real
 * account since, for example through LDAP or SAML. Such names are skipped at
 * login, so the trap no longer works.
 */
class TrapNameCollisionCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly ReservedNames $reservedNames,
		private readonly DecoyService $decoys,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: reserved names and decoys');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('No reserved name or decoy login name belongs to an account.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$names = array_values(array_unique(array_merge($this->reservedNames->collisions(), $this->decoys->loginNameCollisions())));
		if ($names === []) {
			return null;
		}
		sort($names);
		$quoted = implode(', ', array_map(static fn (string $n): string => '"' . $n . '"', $names));
		return new Finding(
			'trap_name_collision',
			Finding::LEVEL_ERROR,
			$l->n('A trap name belongs to a real account', 'Trap names belong to real accounts', count($names)),
			$l->n(
				'%s is reserved or used by a decoy, but is now also the login name of an account, for example from LDAP. It is skipped at login, so this trap does not work, and the person may have been blocked before the account existed.',
				'%s are reserved or used by decoys, but are now also login names of accounts, for example from LDAP. They are skipped at login, so these traps do not work, and the people may have been blocked before the accounts existed.',
				count($names),
				[$quoted],
			),
			$l->t('Remove these names from the reserved names, or delete the decoys that use them, on the Decoys tab. Then choose names no account uses.'),
			'#decoys',
			$l->t('Open the Decoys tab'),
		);
	}
}
