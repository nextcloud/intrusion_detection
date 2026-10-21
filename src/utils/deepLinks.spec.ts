/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { resolveLink } from './deepLinks.ts'

describe('links of the admin page', () => {
	test('the tabs, with a check or a section', () => {
		expect(resolveLink('#overview')).toEqual({ tab: 'overview', check: null, section: null, detection: null, advanced: false })
		expect(resolveLink('#protection/credential_stuffing')).toEqual({ tab: 'protection', check: 'credential_stuffing', section: null, detection: null, advanced: false })
		expect(resolveLink('settings/notifications')).toEqual({ tab: 'settings', check: null, section: 'notifications', detection: null, advanced: false })
		expect(resolveLink('#blocks')).toMatchObject({ tab: 'blocks', section: null })
	})

	test('a detection opens on the overview', () => {
		expect(resolveLink('#detection-42')).toEqual({ tab: 'overview', check: null, section: null, detection: 42, advanced: false })
	})

	test('the links of the former tabs land where their content is now', () => {
		expect(resolveLink('#checks')).toMatchObject({ tab: 'protection', check: null, advanced: false })
		expect(resolveLink('#checks/admin_change')).toMatchObject({ tab: 'protection', check: 'admin_change', section: null })
		expect(resolveLink('#decoys')).toMatchObject({ tab: 'blocks', section: 'decoys', advanced: false })
		expect(resolveLink('#notifications')).toMatchObject({ tab: 'settings', section: 'notifications', advanced: false })
		expect(resolveLink('#confirmation')).toMatchObject({ tab: 'settings', section: 'confirmation', advanced: false })
		expect(resolveLink('#privacy')).toMatchObject({ tab: 'settings', section: 'privacy', advanced: false })
	})

	test('targets shown only with the advanced options say so', () => {
		expect(resolveLink('#incidents')).toMatchObject({ tab: 'incidents', advanced: true })
		expect(resolveLink('#advanced')).toMatchObject({ tab: 'settings', section: 'advanced', advanced: true })
	})

	test('unknown or malformed links are ignored', () => {
		expect(resolveLink('')).toBeNull()
		expect(resolveLink('#approval-3')).toBeNull()
		expect(resolveLink('#protection/a/b')).toBeNull()
		expect(resolveLink('#settings/<script>')).toBeNull()
	})
})
