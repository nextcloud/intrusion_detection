/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import OverviewTab from './OverviewTab.vue'
import { fetchDailyStats, fetchDetections, lookup } from '../services/api.ts'
import { incidentRequest, setAdvanced, state } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDailyStats: vi.fn(),
	fetchDetections: vi.fn(),
	lookup: vi.fn(),
}))

const mounted: { unmount: () => void }[] = []

/**
 * Mount the overview with "ids-show-tab" recorded.
 */
async function mountOverview() {
	const showTab = vi.fn()
	const wrapper = mount(OverviewTab, { attachTo: document.body, global: { provide: { 'ids-show-tab': showTab } } })
	mounted.push(wrapper)
	await flushPromises()
	return { wrapper, showTab }
}

describe('the overview', () => {
	beforeEach(() => {
		Element.prototype.scrollIntoView = vi.fn()
		state.status = makeStatus()
		state.checks = []
		vi.mocked(fetchDetections).mockResolvedValue({ detections: [], hasMore: false })
		vi.mocked(fetchDailyStats).mockResolvedValue({ days: [] } as never)
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		setAdvanced(false)
		window.localStorage.clear()
		state.status = null
		incidentRequest.value = null
		vi.mocked(fetchDailyStats).mockReset()
		vi.mocked(lookup).mockReset()
		document.body.innerHTML = ''
	})

	test('says what happened in one sentence, with what needs attention and the recent activity', async () => {
		const { wrapper } = await mountOverview()
		expect(wrapper.get('[data-test="status-summary"]').text()).toContain('In the last 24 hours: 1,234 detections, 6 addresses would have been blocked.')
		expect(wrapper.find('#ids-section-attention').exists()).toBe(true)
		expect(wrapper.text()).toContain('Recent activity')
		expect(wrapper.text()).toContain('Look up an address or account')
	})

	test('the figures, the chart and the filters only with the advanced options', async () => {
		const { wrapper } = await mountOverview()
		expect(wrapper.find('[data-test="status-figures"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="overview-chart"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="detection-filters"]').exists()).toBe(false)
		expect(fetchDailyStats).not.toHaveBeenCalled()

		setAdvanced(true)
		await flushPromises()
		expect(wrapper.find('[data-test="status-figures"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="overview-chart"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="detection-filters"]').exists()).toBe(true)
		expect(fetchDailyStats).toHaveBeenCalledTimes(1)
	})

	test('a looked-up address gets "Create incident report" with the advanced options', async () => {
		vi.mocked(lookup).mockResolvedValue({ kind: 'address', query: '203.0.113.7', bans: [], detections: [], user: null })
		const { wrapper, showTab } = await mountOverview()
		await wrapper.get('form[role="search"] input').setValue('203.0.113.7')
		await wrapper.get('form[role="search"]').trigger('submit')
		await flushPromises()
		expect(wrapper.find('[data-test="lookup-incident-report"]').exists()).toBe(false)

		setAdvanced(true)
		await flushPromises()
		await wrapper.get('[data-test="lookup-incident-report"]').trigger('click')
		expect(incidentRequest.value).toEqual({ type: 'address', value: '203.0.113.7', since: null, until: null })
		expect(showTab).toHaveBeenCalledWith('incidents')
	})
})
