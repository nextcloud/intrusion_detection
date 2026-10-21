/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { resolveLink } from './deepLinks.ts'

describe('links of the admin page', () => {
	test('the tabs, a check and a section', () => {
		expect(resolveLink('#overview')).toEqual({ tab: 'overview', check: null, section: null, detection: null, advanced: false })
		expect(resolveLink('#protection/credential_stuffing')).toEqual({ tab: 'protection', check: 'credential_stuffing', section: null, detection: null, advanced: false })
		expect(resolveLink('settings-notifications')).toEqual({ tab: 'settings', check: null, section: 'settings-notifications', detection: null, advanced: false })
		expect(resolveLink('#blocks-active')).toMatchObject({ tab: 'blocks', section: 'blocks-active', advanced: false })
		expect(resolveLink('#overview-attention')).toMatchObject({ tab: 'overview', section: 'overview-attention' })
	})

	test('a detection opens on the overview', () => {
		expect(resolveLink('#detection-42')).toEqual({ tab: 'overview', check: null, section: null, detection: 42, advanced: false })
	})

	test('the links of the former tabs land where their content is now', () => {
		expect(resolveLink('#checks')).toMatchObject({ tab: 'protection', check: null, advanced: false })
		expect(resolveLink('#checks/admin_change')).toMatchObject({ tab: 'protection', check: 'admin_change', section: null })
		expect(resolveLink('#decoys')).toMatchObject({ tab: 'blocks', section: 'blocks-decoys', advanced: false })
		expect(resolveLink('#notifications')).toMatchObject({ tab: 'settings', section: 'settings-notifications', advanced: false })
		expect(resolveLink('#confirmation')).toMatchObject({ tab: 'settings', section: 'settings-confirmation', advanced: false })
		expect(resolveLink('#approvals')).toMatchObject({ tab: 'settings', section: 'settings-approvals', advanced: false })
		expect(resolveLink('#privacy')).toMatchObject({ tab: 'settings', section: 'settings-privacy', advanced: false })
		expect(resolveLink('#advanced')).toMatchObject({ tab: 'settings', section: 'settings-learning', advanced: false })
		expect(resolveLink('#accounts')).toMatchObject({ tab: 'settings', section: 'settings-confirmation-accounts', advanced: true })
	})

	test('targets shown only with the advanced options say so', () => {
		expect(resolveLink('#incidents')).toMatchObject({ tab: 'incidents', advanced: true })
		for (const section of ['blocks-trap-paths', 'blocks-firewall', 'blocks-escalation', 'settings-confirmation-reasons', 'settings-support']) {
			expect(resolveLink('#' + section)).toMatchObject({ section, advanced: true })
		}
		expect(resolveLink('#settings-other')).toMatchObject({ section: 'settings-other', advanced: false })
	})

	test('unknown or malformed links are ignored', () => {
		expect(resolveLink('')).toBeNull()
		expect(resolveLink('#approval-3x')).toBeNull()
		expect(resolveLink('#nowhere-else')).toBeNull()
		expect(resolveLink('#protection/a/b')).toBeNull()
		expect(resolveLink('#settings/privacy')).toBeNull()
		expect(resolveLink('#protection/<script>')).toBeNull()
	})
})
