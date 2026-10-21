/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { IncidentEntry, IncidentReport } from '../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import IncidentsTab from './IncidentsTab.vue'
import { ApiError, buildIncidentReport, downloadIncidentReport } from '../services/api.ts'
import { incidentRequest } from '../store.ts'

const mounted: { unmount: () => void }[] = []

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	buildIncidentReport: vi.fn(),
	downloadIncidentReport: vi.fn(),
	searchAccounts: vi.fn(() => Promise.resolve([])),
}))

const AT = Date.UTC(2026, 9, 20, 10, 2) / 1000

/**
 * @param id - Entry id
 * @param kind - Entry kind
 * @param overrides - Fields to change
 */
function entry(id: string, kind: string, overrides: Partial<IncidentEntry> = {}): IncidentEntry {
	return {
		id,
		at: AT,
		endsAt: null,
		kind,
		group: kind,
		title: 'Title of ' + id,
		severity: null,
		enforced: null,
		details: ['Detail of ' + id],
		done: [],
		note: null,
		address: '203.0.113.7',
		accounts: [],
		ref: null,
		...overrides,
	}
}

/**
 * @param overrides - Fields to change
 */
function report(overrides: Partial<IncidentReport> = {}): IncidentReport {
	return {
		schemaVersion: 1,
		generatedAt: AT + 3600,
		generatedBy: 'admin',
		server: 'https://cloud.example.org',
		subject: { type: 'address', value: '203.0.113.7', displayName: null },
		period: { since: AT - 86400, until: AT + 3600 },
		summary: {
			headline: 'Nextcloud recorded 3 events about the address 203.0.113.7.',
			happened: ['Credential stuffing: once, at 10:02'],
			startedAt: AT,
			foundAt: AT,
			lastActivityAt: AT + 60,
			affected: ['The address 203.0.113.7'],
			dataCategories: [],
			dataNote: 'No sign that data was opened: only failed attempts and blocks were recorded.',
			measures: ['Blocked 203.0.113.7 until 14:02.'],
			openItems: ['Check the app passwords created in this period with the account owner.'],
			counts: { entries: 3, detections: 1, enforced: 1, observed: 0 },
		},
		kinds: [
			{ id: 'detection', label: 'Detections', count: 1 },
			{ id: 'block', label: 'Blocks', count: 1 },
			{ id: 'app_password', label: 'App passwords created', count: 1 },
			{ id: 'share', label: 'Shares created', count: 0 },
		],
		entries: [
			entry('detection:1', 'detection', { severity: 'high', enforced: true, title: 'Credential stuffing', done: ['Blocked 203.0.113.7 until 14:02.'] }),
			entry('block:1', 'block', { title: 'Address 203.0.113.7 blocked' }),
			entry('app-password:9', 'app_password', { at: AT + 60, title: 'App password created for alice' }),
		],
		notes: [{ id: 'file_actions', text: 'File actions are recorded per account.', url: null, linkLabel: null }],
		truncated: false,
		maxEntries: 2000,
		...overrides,
	}
}

/**
 * Mount the tab, optionally with a report requested from a detection.
 *
 * @param value - What building the report returns
 */
async function mountTab(value: IncidentReport | Error | null = null) {
	if (value instanceof Error) {
		vi.mocked(buildIncidentReport).mockRejectedValue(value)
	} else if (value !== null) {
		vi.mocked(buildIncidentReport).mockResolvedValue(value)
	}
	if (value !== null) {
		incidentRequest.value = { type: 'address', value: '203.0.113.7', since: null, until: null }
	}
	const wrapper = mount(IncidentsTab, { attachTo: document.body })
	mounted.push(wrapper)
	await flushPromises()
	await flushPromises()
	return wrapper
}

describe('IncidentsTab', () => {
	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(buildIncidentReport).mockReset()
		vi.mocked(downloadIncidentReport).mockReset()
		incidentRequest.value = null
		document.body.innerHTML = ''
	})

	test('asks for a subject before anything is built', async () => {
		const wrapper = await mountTab()
		expect(wrapper.text()).toContain('Choose an account or an address')
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('an invalid address is explained and nothing is requested', async () => {
		const wrapper = await mountTab()
		await wrapper.findAll('input[type="radio"]').find((input) => input.attributes('value') === 'address')!.setValue(true)
		await wrapper.find('input[type="text"]').setValue('203.0.113.0/24')
		await wrapper.find('form').trigger('submit')
		await flushPromises()
		expect(wrapper.text()).toContain('Enter a single IPv4 or IPv6 address')
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('an account must be chosen', async () => {
		const wrapper = await mountTab()
		await wrapper.find('form').trigger('submit')
		await flushPromises()
		expect(wrapper.text()).toContain('Choose an account.')
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('a request from a detection builds the report with summary and timeline', async () => {
		const wrapper = await mountTab(report())
		expect(buildIncidentReport).toHaveBeenCalledWith({ type: 'address', value: '203.0.113.7', since: null, until: null })
		expect(incidentRequest.value).toBeNull()
		expect(wrapper.get('[data-test="incident-subject"]').text()).toBe('Address 203.0.113.7')
		expect(wrapper.get('[data-test="incident-headline"]').text()).toBe('Nextcloud recorded 3 events about the address 203.0.113.7.')
		expect(wrapper.get('[data-test="incident-data"]').text()).toContain('No sign that data was opened')
		expect(wrapper.get('[data-test="incident-measures"]').text()).toContain('Blocked 203.0.113.7 until 14:02.')
		expect(wrapper.get('[data-test="incident-open"]').text()).toContain('Check the app passwords')
		expect(wrapper.findAll('[data-test^="incident-entry-"]')).toHaveLength(3)
		expect(wrapper.text()).toContain('Detail of detection:1')
		expect(wrapper.text()).toContain('File actions are recorded per account.')
		expect(wrapper.find('[data-test="incident-truncated"]').exists()).toBe(false)
	})

	test('filters the timeline by kind, and only kinds with entries are offered', async () => {
		const wrapper = await mountTab(report())
		expect(wrapper.find('[data-test="incident-filter-share"]').exists()).toBe(false)
		await wrapper.get('[data-test="incident-filter-block"]').trigger('click')
		expect(wrapper.findAll('[data-test^="incident-entry-"]').map((e) => e.attributes('data-test'))).toEqual(['incident-entry-block'])
		expect(wrapper.get('[data-test="incident-filter-block"]').attributes('aria-pressed')).toBe('true')
		await wrapper.get('[data-test="incident-filter-app_password"]').trigger('click')
		expect(wrapper.findAll('[data-test^="incident-entry-"]')).toHaveLength(2)
		await wrapper.get('[data-test="incident-filter-all"]').trigger('click')
		expect(wrapper.findAll('[data-test^="incident-entry-"]')).toHaveLength(3)
		expect(wrapper.get('[data-test="incident-filter-all"]').attributes('aria-pressed')).toBe('true')
	})

	test('entries collapse and expand, with aria-expanded', async () => {
		const wrapper = await mountTab(report())
		const toggle = wrapper.get('[data-test="incident-entry-detection"] button[aria-expanded]')
		expect(toggle.attributes('aria-expanded')).toBe('true')
		await toggle.trigger('click')
		expect(toggle.attributes('aria-expanded')).toBe('false')
		expect(wrapper.text()).not.toContain('Detail of detection:1')
	})

	test('a truncated report says so', async () => {
		const wrapper = await mountTab(report({ truncated: true }))
		expect(wrapper.get('[data-test="incident-truncated"]').text()).toContain('Only the first 2000 entries')
	})

	test('an empty report shows an empty timeline', async () => {
		const wrapper = await mountTab(report({ entries: [], kinds: [{ id: 'detection', label: 'Detections', count: 0 }] }))
		expect(wrapper.text()).toContain('Nothing on the timeline')
	})

	test('an error is shown with a way to try again', async () => {
		const wrapper = await mountTab(new ApiError('A report covers at most 90 days. Choose a shorter period.'))
		expect(wrapper.text()).toContain('A report covers at most 90 days.')
		vi.mocked(buildIncidentReport).mockResolvedValue(report())
		await wrapper.findAll('button').find((b) => b.text() === 'Try again')!.trigger('click')
		await flushPromises()
		expect(buildIncidentReport).toHaveBeenCalledTimes(2)
		expect(wrapper.find('[data-test="incident-subject"]').exists()).toBe(true)
	})

	test('downloads use exactly the request the report was built from', async () => {
		const createObjectURL = vi.fn(() => 'blob:report')
		const revokeObjectURL = vi.fn()
		vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }))
		vi.mocked(downloadIncidentReport).mockResolvedValue({ blob: new Blob(['{}']), filename: 'incident-report-203.0.113.7.json' })
		const wrapper = await mountTab(report())
		await wrapper.get('[data-test="incident-download-json"]').trigger('click')
		await flushPromises()
		expect(downloadIncidentReport).toHaveBeenCalledWith({ type: 'address', value: '203.0.113.7', since: null, until: null }, 'json')
		expect(createObjectURL).toHaveBeenCalled()
		vi.unstubAllGlobals()
	})
})
