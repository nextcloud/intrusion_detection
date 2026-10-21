/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { afterEach, describe, expect, test, vi } from 'vitest'
import { advanced, setAdvanced } from './store.ts'

describe('advanced options switch', () => {
	afterEach(() => {
		vi.restoreAllMocks()
		window.localStorage.clear()
	})

	test('is remembered in this browser', () => {
		setAdvanced(true)
		expect(advanced.value).toBe(true)
		expect(window.localStorage.getItem('intrusion_detection.advanced')).toBe('1')
		setAdvanced(false)
		expect(advanced.value).toBe(false)
		expect(window.localStorage.getItem('intrusion_detection.advanced')).toBe('0')
	})

	test('still applies when the browser refuses storage', () => {
		vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
			throw new Error('blocked')
		})
		setAdvanced(true)
		expect(advanced.value).toBe(true)
	})
})
