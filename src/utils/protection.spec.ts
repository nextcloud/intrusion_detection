/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { makeCheck } from '../tests/fixtures.ts'
import { protectionGroups } from './protection.ts'

describe('the groups of the Protection tab', () => {
	test('four groups made of the categories, in their order, without empty ones', () => {
		const checks = [
			makeCheck({ id: 'trap_url', category: 'traps' }),
			makeCheck({ id: 'credential_stuffing', category: 'login_attacks' }),
			makeCheck({ id: 'admin_change', category: 'administration' }),
			makeCheck({ id: 'account_takeover', category: 'devices_sessions' }),
			makeCheck({ id: 'blocklist_match', category: 'addresses_requests' }),
		]
		const groups = protectionGroups(checks)
		expect(groups.map((group) => group.name)).toEqual(['Logins and passwords', 'Scanning and probing', 'Accounts and administration'])
		expect(groups[1]!.checks.map((check) => check.id)).toEqual(['trap_url', 'blocklist_match'])
		expect(groups[2]!.checks.map((check) => check.id)).toEqual(['admin_change', 'account_takeover'])
	})

	test('share links and password reset are under Sharing; unknown categories under Other', () => {
		const groups = protectionGroups([makeCheck({ id: 'share_bruteforce', category: 'shares_reset' }), makeCheck({ id: 'future', category: 'something_new' })])
		expect(groups.map((group) => [group.id, group.checks.length])).toEqual([['sharing', 1], ['other', 1]])
	})
})
