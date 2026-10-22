/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import ActivityTimeline from './ActivityTimeline.vue'
import { activity, activityItem, login, NOW, securityChange, securityEvent } from '../../tests/personalFixtures.ts'
import { fetchActivity } from '../api.ts'
import { ACTIVITY_PAGE, personal, reloadActivity } from '../store.ts'

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchActivity: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('ActivityTimeline', () => {
	beforeEach(() => {
		personal.activity = null
		personal.activityLimit = ACTIVITY_PAGE
	})

	afterEach(() => {
		vi.mocked(fetchActivity).mockReset()
	})

	test('shows the days with their entries under one heading', () => {
		personal.activity = activity({
			items: [
				activityItem({ change: securityChange(1, { createdAt: NOW - 60, detail: 'TOTP', label: 'Second factor added' }) }),
				activityItem({ login: login(1, { createdAt: NOW - 600, current: true }) }),
				activityItem({ failed: 3, at: NOW - 86400 }),
				activityItem({ login: login(2, { createdAt: NOW - 86400 * 6, confirmedBy: 'email_code' }) }),
			],
		})
		const wrapper = mount(ActivityTimeline)

		expect(wrapper.get('h3').text()).toBe('Recent activity')
		expect(wrapper.findAll('h4').map((h) => h.text())).toEqual(['Today', 'Yesterday', 'Thursday, October 15'])
		const today = wrapper.get('[data-test="day-2026-10-21"]')
		expect(today.findAll('li').map((li) => li.attributes('data-test'))).toEqual(['activity-change-1', 'activity-login-1'])
		expect(today.get('[data-test="activity-change-1"]').text()).toContain('Second factor added')
		expect(today.get('[data-test="activity-change-1"]').text()).toContain('by you')
		expect(today.get('[data-test="activity-login-1"]').text()).toContain('This session')
		expect(wrapper.get('[data-test="activity-failed-2026-10-20"]').text()).toContain('3 failed logins with a wrong password')
		expect(wrapper.get('[data-test="activity-failed-2026-10-20"]').text()).toContain('the last one at')
		expect(wrapper.get('[data-test="activity-login-2"]').text()).toContain('Confirmed with an email code')
		expect(wrapper.find('[data-test="show-more"]').exists()).toBe(false)
	})

	test('shows an answered question with its answer and its details on demand', async () => {
		personal.activity = activity({
			items: [activityItem({ event: securityEvent(1, { asks: true, verdict: 'confirmed', verdictAt: NOW }) })],
		})
		const wrapper = mount(ActivityTimeline)
		const row = wrapper.get('[data-test="activity-event-1"]')

		expect(row.get('[data-test="answer"]').text()).toBe('You answered "Yes, it was me".')
		expect(row.find('[data-test="question"]').exists()).toBe(false)
		const toggle = row.get('[data-test="toggle"] button')
		expect(toggle.attributes('aria-expanded')).toBe('false')
		await toggle.trigger('click')
		expect(row.get('[data-test="details"]').text()).toContain('What Nextcloud did')
	})

	test('"Show more" loads the next entries', async () => {
		personal.activity = activity({ items: [activityItem({ login: login(1) })], hasMore: true })
		vi.mocked(fetchActivity).mockResolvedValue(activity({ items: [activityItem({ login: login(1) }), activityItem({ login: login(2) })] }))
		const wrapper = mount(ActivityTimeline)

		await wrapper.get('[data-test="show-more"]').trigger('click')
		await flushPromises()

		expect(fetchActivity).toHaveBeenCalledWith(ACTIVITY_PAGE * 2, 30, expect.any(AbortSignal))
		expect(personal.activityLimit).toBe(ACTIVITY_PAGE * 2)
		expect(wrapper.find('[data-test="activity-login-2"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="show-more"]').exists()).toBe(false)
	})

	test('stops offering more at the server\'s bound', () => {
		personal.activity = activity({ items: [activityItem({ login: login(1) })], hasMore: true })
		personal.activityLimit = 100
		const wrapper = mount(ActivityTimeline)
		expect(wrapper.find('[data-test="show-more"]').exists()).toBe(false)
	})

	test('is left out, heading and all, while loading and when there is no news', () => {
		expect(mount(ActivityTimeline).html()).toBe('<!--v-if-->')
		personal.activity = activity()
		expect(mount(ActivityTimeline).find('[data-test="activity"]').exists()).toBe(false)
		personal.activity = activity({ items: [activityItem({ login: login(1, { current: true }) })] })
		expect(mount(ActivityTimeline).find('[data-test="activity"]').exists(), 'This session alone is no news').toBe(false)
	})

	test('says when the activity could not be loaded, and tries again', async () => {
		vi.mocked(fetchActivity).mockRejectedValueOnce(new Error('offline'))
		await reloadActivity()
		vi.mocked(fetchActivity).mockResolvedValue(activity({ items: [activityItem({ login: login(1) })] }))
		const wrapper = mount(ActivityTimeline)
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('could not be loaded')
		await wrapper.get('[data-test="load-error"] button').trigger('click')
		await flushPromises()
		expect(fetchActivity).toHaveBeenLastCalledWith(ACTIVITY_PAGE, 30, expect.any(AbortSignal))
		expect(wrapper.find('[data-test="activity-login-1"]').exists()).toBe(true)
	})
})
