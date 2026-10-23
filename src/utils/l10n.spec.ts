/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { APP_ID } from './format.ts'
import { n, t } from './l10n.ts'

const NAME = 'Tom\'s & Co <b>'

describe('t', () => {
	test('fills in a name with & and \' as it is', () => {
		expect(t(APP_ID, 'Remove {name}', { name: NAME })).toBe('Remove Tom\'s & Co <b>')
	})

	test('keeps & in a text without placeholders', () => {
		expect(t(APP_ID, 'Logins & sessions')).toBe('Logins & sessions')
	})

	test('replaces %n', () => {
		expect(t(APP_ID, '%n left', undefined, 3)).toBe('3 left')
	})
})

describe('n', () => {
	test('picks the form and fills in a name as it is', () => {
		expect(n(APP_ID, '{name} has %n device', '{name} has %n devices', 1, { name: NAME })).toBe('Tom\'s & Co <b> has 1 device')
		expect(n(APP_ID, '{name} has %n device', '{name} has %n devices', 2, { name: NAME })).toBe('Tom\'s & Co <b> has 2 devices')
	})
})
