/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import OpenQuestions from './OpenQuestions.vue'
import { snowflake } from '../../tests/fixtures.ts'
import { activity, activityItem, NOW, overview, securityEvent } from '../../tests/personalFixtures.ts'
import { confirmEvent, fetchActivity, fetchOverview } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	confirmEvent: vi.fn(),
	fetchActivity: vi.fn(),
	fetchOverview: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('OpenQuestions', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.activity = null
		personal.manage = { devices: 0, networks: 0, otherBrowsers: 0 }
		vi.mocked(fetchOverview).mockResolvedValue(overview())
	})

	afterEach(() => {
		vi.mocked(confirmEvent).mockReset()
		vi.mocked(fetchActivity).mockReset()
	})

	test('lists only the questions still waiting for an answer', () => {
		personal.activity = activity({
			questions: [
				securityEvent(1, { asks: true, canConfirm: true }),
				securityEvent(2, { asks: true, verdict: 'denied', verdictAt: NOW }),
			],
		})
		const wrapper = mount(OpenQuestions)

		expect(wrapper.get('h3').text()).toBe('Was this you?')
		expect(wrapper.find(`[data-test="event-${snowflake(1)}"] [data-test="question"]`).exists()).toBe(true)
		expect(wrapper.find(`[data-test="event-${snowflake(2)}"]`).exists()).toBe(false)
	})

	test('an answered question leaves, and the timeline then has it with its answer', async () => {
		const answered = securityEvent(1, { asks: true, verdict: 'confirmed', verdictAt: NOW })
		personal.activity = activity({ questions: [securityEvent(1, { asks: true, canConfirm: true })] })
		vi.mocked(confirmEvent).mockResolvedValue(answered)
		vi.mocked(fetchActivity).mockResolvedValue(activity({ items: [activityItem({ event: answered })] }))
		const wrapper = mount(OpenQuestions)

		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()

		expect(fetchActivity).toHaveBeenCalled()
		expect(personal.activity?.questions).toEqual([])
		expect(personal.activity?.items[0].event?.verdict).toBe('confirmed')
		expect(personal.manage.networks, 'Manage now offers the trusted network').toBe(1)
		expect(wrapper.find('[data-test="questions"]').exists()).toBe(false)
	})

	test('is left out, heading and all, without open questions', () => {
		expect(mount(OpenQuestions).find('h3').exists(), 'While loading').toBe(false)
		personal.activity = activity({ items: [activityItem({ event: securityEvent(1) })] })
		expect(mount(OpenQuestions).find('[data-test="questions"]').exists()).toBe(false)
	})
})
