/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import SecurityEvents from './SecurityEvents.vue'
import { overview, securityEvent } from '../../tests/personalFixtures.ts'
import { fetchEvents } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchEvents: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('SecurityEvents', () => {
	beforeEach(() => {
		personal.overview = overview()
	})

	afterEach(() => {
		vi.mocked(fetchEvents).mockReset()
	})

	test('shows skeletons while loading', () => {
		vi.mocked(fetchEvents).mockReturnValue(new Promise(() => {}))
		const wrapper = mount(SecurityEvents)
		expect(wrapper.find('[data-test="loading"]').attributes('aria-busy')).toBe('true')
	})

	test('says so encouragingly when nothing happened', async () => {
		vi.mocked(fetchEvents).mockResolvedValue([])
		const wrapper = mount(SecurityEvents)
		await flushPromises()
		expect(wrapper.get('[data-test="events-empty"]').text()).toContain('No security events')
		expect(wrapper.find('[data-test="events-open"]').exists()).toBe(false)
	})

	test('explains a failure and loads again on request', async () => {
		vi.mocked(fetchEvents).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([securityEvent(1)])
		const wrapper = mount(SecurityEvents)
		await flushPromises()
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('Your security events could not be loaded')
		await wrapper.get('[data-test="load-error"] button').trigger('click')
		await flushPromises()
		expect(wrapper.find('[data-test="load-error"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="event-1"]').exists()).toBe(true)
	})

	test('puts open questions first and counts them', async () => {
		vi.mocked(fetchEvents).mockResolvedValue([
			securityEvent(1),
			securityEvent(2, { asks: true, verdict: 'confirmed', verdictAt: 1 }),
			securityEvent(3, { asks: true }),
		])
		const wrapper = mount(SecurityEvents)
		await flushPromises()
		expect(wrapper.findAll('li[data-test^="event-"]').map((li) => li.attributes('data-test'))).toEqual(['event-3', 'event-1', 'event-2'])
		expect(wrapper.get('[data-test="events-open"]').text()).toBe('1 needs your answer')
	})

	test('shows the newest five and the rest on request', async () => {
		vi.mocked(fetchEvents).mockResolvedValue(Array.from({ length: 7 }, (_, i) => securityEvent(i + 1)))
		const wrapper = mount(SecurityEvents)
		await flushPromises()
		expect(wrapper.findAll('li[data-test^="event-"]')).toHaveLength(5)
		const more = wrapper.findAll('button').find((b) => b.text() === 'Show all 7 events')!
		expect(more.attributes('aria-expanded')).toBe('false')
		await more.trigger('click')
		expect(wrapper.findAll('li[data-test^="event-"]')).toHaveLength(7)
	})
})
