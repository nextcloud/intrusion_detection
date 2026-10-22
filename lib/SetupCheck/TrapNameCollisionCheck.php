<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\IL10N;

/**
 * A reserved login name or the login name of a decoy has become a real
 * account since, for example through LDAP or SAML. Such names are skipped at
 * login, so the trap no longer works. Reads the stored lookup
 * ({@see TrapNameCollisions}), which the hourly job and every change of the
 * names refresh.
 *
 * Otherwise it points out that no name is reserved while the decoy admin
 * account check runs, as on installs from before names were reserved at
 * installation. That reads the list only, without looking names up.
 */
class TrapNameCollisionCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly TrapNameCollisions $collisions,
		private readonly CheckSettings $settings,
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
		$names = $this->collisions->all();
		if ($names === []) {
			return $this->noReservedNames($l);
		}
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
			$l->t('Remove these names from the reserved names, or delete the decoys that use them, on the Blocks tab. Then choose names no account uses.'),
			'#blocks-decoys',
			$l->t('Open the decoys'),
		);
	}

	private function noReservedNames(IL10N $l): ?Finding {
		if (!$this->settings->modeState(ReservedName::ID)->runs() || $this->settings->paramList(ReservedName::ID, 'names') !== []) {
			return null;
		}
		return new Finding(
			'reserved_names_empty',
			Finding::LEVEL_INFO,
			$l->t('No login names are reserved yet'),
			$l->t('The decoy admin account check blocks anyone who tries a name such as "administrator" or "root" that no account uses. No name is reserved, so it does nothing.'),
			$l->t('Reserve the suggested names on the Blocks tab with "Add all", or run occ intrusion:reserved-names --add-suggested.'),
			'#blocks-reserved',
			$l->t('Open the reserved names'),
		);
	}
}
