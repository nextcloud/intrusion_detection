/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test } from 'vitest'
import FailedLogins from './FailedLogins.vue'
import { failedDays, NOW, overview } from '../../tests/personalFixtures.ts'
import { personal } from '../store.ts'

enableAutoUnmount(afterEach)

describe('FailedLogins', () => {
	test('says so calmly when there were none', () => {
		personal.overview = overview()
		const wrapper = mount(FailedLogins)
		expect(wrapper.get('[data-test="empty"]').text()).toBe('No failed logins in the last 30 days.')
		expect(wrapper.find('[data-test="bars"]').exists()).toBe(false)
	})

	test('shows one bar per day, the places and the most recent addresses', async () => {
		personal.overview = overview({
			failedLogins: {
				days: failedDays({ 3: 2, 29: 5 }),
				total: 7,
				places: 3,
				placesCapped: false,
				recent: [{ address: '203.0.113.9', lastSeenAt: NOW - 60 }, { address: '2001:db8::/64', lastSeenAt: NOW - 7200 }],
				timezone: 'Europe/Berlin',
			},
		})
		const wrapper = mount(FailedLogins)
		expect(wrapper.get('[data-test="failed-summary"]').text()).toContain('7')
		expect(wrapper.get('[data-test="failed-summary"]').text()).toContain('failed logins in the last 30 days. They came from 3 different places.')
		const bars = wrapper.get('[data-test="bars"]')
		expect(bars.findAll(':scope > span')).toHaveLength(30)
		expect(bars.attributes('role')).toBe('img')
		expect(wrapper.findAll('table tbody tr')).toHaveLength(30)
		expect(wrapper.findAll('table tbody tr')[29]!.text()).toContain('5')
		expect(wrapper.get('[data-test="recent-addresses"]').text()).toContain('203.0.113.9')
		expect(wrapper.get('[data-test="recent-addresses"]').text()).toContain('2001:db8::/64')

		await bars.trigger('focus')
		expect(wrapper.get('[data-test="bars-readout"]').text()).toContain('5 failed logins')
		await bars.trigger('keydown', { key: 'Home' })
		expect(wrapper.get('[data-test="bars-readout"]').text()).toContain('0 failed logins')
		await bars.trigger('keydown', { key: 'ArrowRight' })
		await bars.trigger('keydown', { key: 'ArrowRight' })
		await bars.trigger('keydown', { key: 'ArrowRight' })
		expect(wrapper.get('[data-test="bars-readout"]').text()).toContain('2 failed logins')
	})

	test('says "at least" when a day kept only some of the places', () => {
		personal.overview = overview({
			failedLogins: { days: failedDays({ 29: 400 }), total: 400, places: 20, placesCapped: true, recent: [], timezone: 'UTC' },
		})
		expect(mount(FailedLogins).get('[data-test="failed-summary"]').text()).toContain('They came from at least 20 different places.')
	})
})
