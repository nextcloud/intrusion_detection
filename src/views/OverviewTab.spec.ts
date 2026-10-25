/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import OverviewTab from './OverviewTab.vue'
import { approveRequest, fetchAdminGrants, fetchDailyStats, fetchDetections, fetchLearningRecap, fetchWaitingLogins, lookup, rejectRequest } from '../services/api.ts'
import { adminGrants, incidentRequest, state, waitingLogins } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDailyStats: vi.fn(),
	fetchDetections: vi.fn(),
	fetchLearningRecap: vi.fn(() => Promise.resolve(null)),
	fetchWaitingLogins: vi.fn(() => Promise.resolve([])),
	fetchAdminGrants: vi.fn(() => Promise.resolve([])),
	approveRequest: vi.fn(),
	rejectRequest: vi.fn(),
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
		state.status = null
		incidentRequest.value = null
		waitingLogins.value = []
		adminGrants.value = []
		vi.mocked(approveRequest).mockReset()
		vi.mocked(rejectRequest).mockReset()
		vi.mocked(fetchDailyStats).mockReset()
		vi.mocked(lookup).mockReset()
		document.body.innerHTML = ''
	})

	test('shows the last 24 hours in figures, with what needs attention and the recent activity', async () => {
		const { wrapper } = await mountOverview()
		const summary = wrapper.get('[data-test="status-summary"]')
		expect(summary.get('h3').text()).toBe('Last 24 hours')
		expect(summary.text()).not.toContain('In the last 24 hours:')
		expect(summary.get('[data-test="status-figures"]').text()).toContain('1,234')
		expect(summary.text()).toContain('account targeted')
		expect(summary.text()).not.toContain('concerned')
		expect(summary.text()).not.toContain('Cost')
		expect(wrapper.find('#overview-attention').exists()).toBe(true)
		expect(wrapper.text()).toContain('Recent activity')
		expect(wrapper.text()).toContain('Look up an address or account')
	})

	test('the recap of the learning period comes first, once learning ended', async () => {
		const { wrapper } = await mountOverview()
		expect(wrapper.find('[data-test="learning-recap"]').exists()).toBe(false)
		wrapper.unmount()
		mounted.splice(0)

		vi.mocked(fetchLearningRecap).mockResolvedValueOnce({
			startedAt: 1_760_000_000,
			endedAt: 1_760_604_800,
			days: 7,
			first: true,
			attempts: 0,
			addresses: 0,
			topAttack: null,
			wouldHaveBlocked: 0,
			ownPeople: 0,
			accounts: [],
			complete: true,
		})
		const { wrapper: ended } = await mountOverview()
		const first = ended.get('section')
		expect(first.attributes('id')).toBe('overview-recap')
		expect(first.text()).toContain('A quiet first week: nothing to block.')
	})

	test('the empty address and account filters show an example', async () => {
		const { wrapper } = await mountOverview()
		const placeholders = wrapper.get('[data-test="detection-filters"]').findAll('input[type="text"]').map((input) => input.attributes('placeholder'))
		expect(placeholders).toEqual(['e.g. 203.0.113.5', 'e.g. alice'])
	})

	test('only real problems need attention; tips are listed further down', async () => {
		const { wrapper } = await mountOverview()
		const attention = wrapper.get('#overview-attention').text()
		expect(attention).toContain('Nextcloud cannot send emails')
		expect(attention).not.toContain('No memory cache')
		expect(wrapper.get('[data-test="overview-tips"]').text()).toContain('No memory cache')
	})

	test('a login waiting for this administrator needs attention first, with Approve and Reject', async () => {
		state.status = makeStatus({ state: 'protecting', problems: [] })
		waitingLogins.value = [
			{ id: '7', uid: 'alice', displayName: 'Alice Liddell', ip: '203.0.113.9', createdAt: 1_760_000_000, expiresAt: 1_760_001_800, canDecide: true },
			{ id: '8', uid: 'admin', displayName: 'Admin', ip: null, createdAt: 1_760_000_100, expiresAt: 1_760_001_900, canDecide: false },
		]
		vi.mocked(rejectRequest).mockResolvedValue({})
		vi.mocked(fetchWaitingLogins).mockResolvedValue([])
		const { wrapper } = await mountOverview()
		const attention = wrapper.get('#overview-attention')
		expect(attention.text()).toContain('Needs attention')
		const waiting = attention.get('[data-test="overview-waiting"]')
		expect(waiting.text()).toContain('Alice Liddell')
		expect(waiting.text()).not.toContain('Your own login')
		expect(waiting.findAll('button').map((b) => b.text())).toEqual(['Reject', 'Approve'])
		await waiting.findAll('button')[0]!.trigger('click')
		await flushPromises()
		expect(rejectRequest).toHaveBeenCalledWith('7')
		expect(approveRequest).not.toHaveBeenCalled()
		expect(fetchWaitingLogins).toHaveBeenCalled()
		expect(wrapper.find('#overview-attention').exists()).toBe(false)
	})

	test('an account waiting to become an administrator needs attention; approving asks first', async () => {
		state.status = makeStatus({ state: 'protecting', problems: [] })
		adminGrants.value = [
			{ id: '7', uid: 'bob', displayName: 'Bob Builder', group: 'admin', requestedBy: 'alice', requesterName: 'Alice Liddell', createdAt: 1_760_000_000, expiresAt: 1_760_604_800, canApprove: true },
		]
		vi.mocked(approveRequest).mockResolvedValue({})
		vi.mocked(fetchAdminGrants).mockResolvedValue([])
		const { wrapper } = await mountOverview()
		const card = wrapper.get('#overview-attention').get('#approval-7')
		expect(card.text()).toContain('Alice Liddell asks to make Bob Builder an administrator')
		expect(card.findAll('button').map((b) => b.text())).toEqual(['Reject', 'Approve'])

		await card.findAll('button')[1]!.trigger('click')
		await flushPromises()
		expect(approveRequest).not.toHaveBeenCalled()
		const dialog = document.body.querySelector('[role="dialog"]')
		expect(dialog?.textContent).toContain('Make Bob Builder an administrator?')
		const approve = [...dialog!.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Approve')
		approve!.click()
		await flushPromises()
		expect(approveRequest).toHaveBeenCalledWith('7')
		expect(fetchAdminGrants).toHaveBeenCalled()
		expect(wrapper.find('#overview-attention').exists()).toBe(false)
	})

	test('a request for a new administrator is rejected in one click, and the one who asked can only withdraw it', async () => {
		state.status = makeStatus({ state: 'protecting', problems: [] })
		adminGrants.value = [
			{ id: '7', uid: 'bob', displayName: 'Bob Builder', group: 'admin', requestedBy: 'alice', requesterName: 'Alice Liddell', createdAt: 1_760_000_000, expiresAt: 1_760_604_800, canApprove: true },
			{ id: '8', uid: 'dave', displayName: 'Dave', group: 'admin', requestedBy: 'admin', requesterName: 'Admin', createdAt: 1_760_000_100, expiresAt: 1_760_604_900, canApprove: false },
		]
		vi.mocked(rejectRequest).mockResolvedValue({})
		vi.mocked(fetchAdminGrants).mockResolvedValue([])
		const { wrapper } = await mountOverview()
		const own = wrapper.get('#approval-8')
		expect(own.text()).toContain('Your request: another administrator approves')
		expect(own.findAll('button').map((b) => b.text())).toEqual(['Withdraw'])

		await wrapper.get('#approval-7').findAll('button')[0]!.trigger('click')
		await flushPromises()
		expect(rejectRequest).toHaveBeenCalledWith('7')
		expect(approveRequest).not.toHaveBeenCalled()
		expect(document.body.querySelector('[role="dialog"]')).toBeNull()
	})

	test('nothing asks for attention while the defaults fit', async () => {
		state.status = makeStatus({ state: 'protecting', problems: [{ id: 'cache', level: 'info', title: 'No memory cache', text: '', url: null, urlLabel: null }] })
		const { wrapper } = await mountOverview()
		expect(wrapper.find('#overview-attention').exists()).toBe(false)
		expect(wrapper.text()).not.toContain('Needs attention')
		expect(wrapper.get('[data-test="overview-tips"]').text()).toContain('No memory cache')
	})

	test('the figures, the filters and, below the recent activity, the chart', async () => {
		const { wrapper } = await mountOverview()
		expect(wrapper.find('[data-test="status-figures"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="overview-chart"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="detection-filters"]').exists()).toBe(true)
		expect(fetchDailyStats).toHaveBeenCalledTimes(1)
	})

	test('a looked-up address gets "Create incident report"', async () => {
		vi.mocked(lookup).mockResolvedValue({ kind: 'address', query: '203.0.113.7', bans: [], detections: [], user: null })
		const { wrapper, showTab } = await mountOverview()
		await wrapper.get('form[role="search"] input').setValue('203.0.113.7')
		await wrapper.get('form[role="search"]').trigger('submit')
		await flushPromises()
		await wrapper.get('[data-test="lookup-incident-report"]').trigger('click')
		expect(incidentRequest.value).toEqual({ type: 'address', value: '203.0.113.7', since: null, until: null })
		expect(showTab).toHaveBeenCalledWith('incidents')
	})
})
