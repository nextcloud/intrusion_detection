/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test } from 'vitest'
import StatusLine from './StatusLine.vue'
import { overview } from '../../tests/personalFixtures.ts'
import { personal } from '../store.ts'

enableAutoUnmount(afterEach)

describe('StatusLine', () => {
	test('is calm when nothing happened', () => {
		personal.overview = overview()
		const wrapper = mount(StatusLine)
		expect(wrapper.get('[data-test="status-headline"]').text()).toBe('No unusual activity in the last 30 days')
		expect(wrapper.classes().some((c) => c.includes('status_ok'))).toBe(true)
		expect(wrapper.find('ul').exists()).toBe(false)
		expect(wrapper.get('[role="status"]').attributes('aria-live')).toBe('polite')
	})

	test('names what needs the user first, and the rest below', () => {
		personal.overview = overview({
			status: {
				level: 'warning',
				headline: 'One event needs your answer: was this you?',
				items: [
					{ id: 'protected', level: 'warning', text: 'Your account is under extra protection until 14:00.', at: 1 },
					{ id: 'failed_logins', level: 'info', text: '12 failed logins in the last 30 days.', at: null },
				],
			},
		})
		const wrapper = mount(StatusLine)
		expect(wrapper.get('[data-test="status-headline"]').text()).toBe('One event needs your answer: was this you?')
		expect(wrapper.classes().some((c) => c.includes('status_warning'))).toBe(true)
		expect(wrapper.get('[data-test="status-protected"]').text()).toContain('until 14:00')
		expect(wrapper.get('[data-test="status-failed_logins"]').text()).toContain('12 failed logins')
		expect(wrapper.findAll('[data-test^="status-"] svg').length).toBeGreaterThan(0)
	})

	test('shows information as such', () => {
		personal.overview = overview({ status: { level: 'info', headline: '2 security events in the last 30 days.', items: [] } })
		expect(mount(StatusLine).classes().some((c) => c.includes('status_info'))).toBe(true)
	})

	test('renders nothing without an overview', () => {
		personal.overview = null
		expect(mount(StatusLine).find('[data-test="status"]').exists()).toBe(false)
	})
})
