/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Check } from '../types.ts'

import { APP_ID } from './format.ts'
import { t } from './l10n.ts'

export interface ProtectionGroup {
	id: string
	name: string
	checks: Check[]
}

/**
 * The four groups of the Protection tab, made of the check categories of
 * the server (`lib/Check/Category.php`):
 *
 * - Logins and passwords: login_attacks
 * - Sharing: shares_reset (share links and password reset, the two public
 *   forms anyone can try without an account)
 * - Scanning and probing: traps, addresses_requests
 * - Accounts and administration: devices_sessions, inside_account, administration
 *
 * A category the server adds later is shown under "Other".
 */
const GROUPS: { id: string, name: () => string, categories: string[] }[] = [
	{ id: 'logins', name: () => t(APP_ID, 'Logins and passwords'), categories: ['login_attacks'] },
	{ id: 'sharing', name: () => t(APP_ID, 'Sharing'), categories: ['shares_reset'] },
	{ id: 'scanning', name: () => t(APP_ID, 'Scanning and probing'), categories: ['traps', 'addresses_requests'] },
	{ id: 'accounts', name: () => t(APP_ID, 'Accounts and administration'), categories: ['devices_sessions', 'inside_account', 'administration'] },
]

/**
 * The checks in their groups, in the order the server lists them; empty
 * groups are left out.
 *
 * @param checks - The configurable checks
 */
export function protectionGroups(checks: Check[]): ProtectionGroup[] {
	const known = GROUPS.flatMap((group) => group.categories)
	const groups = GROUPS.map((group) => ({ id: group.id, name: group.name(), checks: checks.filter((check) => group.categories.includes(check.category)) }))
	groups.push({ id: 'other', name: t(APP_ID, 'Other'), checks: checks.filter((check) => !known.includes(check.category)) })
	return groups.filter((group) => group.checks.length > 0)
}
