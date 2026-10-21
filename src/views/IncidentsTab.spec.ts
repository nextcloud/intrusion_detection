/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection, IncidentEntry, IncidentReport } from '../types.ts'

import { PasswordConfirmationCancelledError } from '@nextcloud/password-confirmation'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import IncidentForm from '../components/incidents/IncidentForm.vue'
import IncidentsTab from './IncidentsTab.vue'
import { ApiError, buildIncidentReport, downloadIncidentReport, fetchDetections } from '../services/api.ts'
import { incidentRequest } from '../store.ts'
import { makeDetail } from '../tests/fixtures.ts'

const mounted: { unmount: () => void }[] = []

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	buildIncidentReport: vi.fn(),
	downloadIncidentReport: vi.fn(),
	fetchDetections: vi.fn(),
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
		lastSeenAt: null,
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

/**
 * @param overrides - Fields to change
 */
function detection(overrides: Partial<Detection> = {}): Detection {
	return { ...makeDetail().detection, ...overrides }
}

/**
 * The form in the "New incident report" dialog.
 *
 * @param wrapper - The mounted tab
 */
async function openForm(wrapper: Awaited<ReturnType<typeof mountTab>>) {
	await wrapper.get('[data-test="incident-new"]').trigger('click')
	await flushPromises()
	return wrapper.getComponent(IncidentForm)
}

describe('IncidentsTab', () => {
	beforeEach(() => {
		vi.mocked(fetchDetections).mockResolvedValue({ detections: [], hasMore: false })
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(buildIncidentReport).mockReset()
		vi.mocked(downloadIncidentReport).mockReset()
		vi.mocked(fetchDetections).mockReset()
		incidentRequest.value = null
		document.body.innerHTML = ''
	})

	test('without recent incidents it is calm, with one way to start a report', async () => {
		const wrapper = await mountTab()
		expect(wrapper.get('[data-test="incidents-empty"]').text()).toContain('No incidents in the last 7 days')
		expect(wrapper.findAll('[data-test="incident-new"]')).toHaveLength(1)
		expect(wrapper.find('form').exists()).toBe(false)
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('lists the addresses and accounts of the last 7 days with status, severity and time; nothing is built until one is chosen', async () => {
		vi.mocked(fetchDetections).mockResolvedValue({
			detections: [
				detection({ id: 1, ip: '203.0.113.7', severity: 'high', enforced: true, lastSeenAt: AT }),
				detection({ id: 2, ip: null, uid: 'alice', severity: 'low', enforced: false, checkName: 'Admin change alerts', lastSeenAt: AT - 60 }),
			],
			hasMore: false,
		})
		const wrapper = await mountTab()
		expect(vi.mocked(fetchDetections).mock.calls[0]![1]).toBeLessThanOrEqual(100)
		const items = wrapper.findAll('[data-test="incident-subject-item"]')
		expect(items.map((item) => item.text())).toEqual([
			expect.stringContaining('Address 203.0.113.7'),
			expect.stringContaining('Account alice'),
		])
		expect(items[0]!.text()).toContain('High')
		expect(items[0]!.text()).toContain('Acted on')
		expect(items[1]!.text()).toContain('Observed')
		expect(wrapper.find('[data-test="incident-placeholder"]').exists()).toBe(true)
		expect(buildIncidentReport).not.toHaveBeenCalled()

		vi.mocked(buildIncidentReport).mockResolvedValue(report())
		await items[0]!.trigger('click')
		await flushPromises()
		expect(buildIncidentReport).toHaveBeenCalledWith({ type: 'address', value: '203.0.113.7', since: null, until: null })
		expect(wrapper.findAll('[data-test="incident-subject-item"]')[0]!.attributes('aria-current')).toBe('true')
		expect(document.activeElement).toBe(wrapper.get('[data-test="incident-subject"]').element)
	})

	test('"New incident report" opens the form in a dialog; an invalid address is explained and nothing is requested', async () => {
		const wrapper = await mountTab()
		const form = await openForm(wrapper)
		await form.findAll('input[type="radio"]').find((input) => input.attributes('value') === 'address')!.setValue(true)
		await form.find('input[type="text"]').setValue('203.0.113.0/24')
		await form.find('form').trigger('submit')
		await flushPromises()
		expect(form.text()).toContain('Enter a single IPv4 or IPv6 address')
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('an account must be chosen', async () => {
		const wrapper = await mountTab()
		const form = await openForm(wrapper)
		await form.find('form').trigger('submit')
		await flushPromises()
		expect(form.text()).toContain('Choose an account.')
		expect(buildIncidentReport).not.toHaveBeenCalled()
	})

	test('a valid form closes the dialog and builds the report', async () => {
		vi.mocked(buildIncidentReport).mockResolvedValue(report())
		const wrapper = await mountTab()
		const form = await openForm(wrapper)
		await form.findAll('input[type="radio"]').find((input) => input.attributes('value') === 'address')!.setValue(true)
		await form.find('input[type="text"]').setValue('203.0.113.7')
		await form.find('form').trigger('submit')
		await flushPromises()
		expect(wrapper.findComponent(IncidentForm).exists()).toBe(false)
		expect(buildIncidentReport).toHaveBeenCalledWith(expect.objectContaining({ type: 'address', value: '203.0.113.7' }))
		expect(wrapper.get('[data-test="incident-subject"]').text()).toBe('Address 203.0.113.7')
	})

	test('"Change period" keeps a chosen period, and a period in the past is shown as custom dates', async () => {
		vi.mocked(buildIncidentReport).mockResolvedValue(report())
		const now = Math.floor(Date.now() / 1000)
		incidentRequest.value = { type: 'address', value: '203.0.113.7', since: now - 30 * 86400, until: now }
		const wrapper = await mountTab()
		await wrapper.get('[data-test="incident-change"]').trigger('click')
		await flushPromises()
		const radio = (value: string) => wrapper.getComponent(IncidentForm).findAll('input[type="radio"]').find((input) => input.attributes('value') === value)!.element
		expect(radio('30')).toHaveProperty('checked', true)

		wrapper.getComponent(IncidentForm).vm.$emit('build', { type: 'address', value: '203.0.113.7', since: now - 40 * 86400, until: now - 10 * 86400 })
		await flushPromises()
		await wrapper.get('[data-test="incident-change"]').trigger('click')
		await flushPromises()
		expect(radio('custom')).toHaveProperty('checked', true)
	})

	test('"Change period" opens the form with the shown report\'s subject', async () => {
		const wrapper = await mountTab(report())
		await wrapper.get('[data-test="incident-change"]').trigger('click')
		await flushPromises()
		const form = wrapper.getComponent(IncidentForm)
		expect((form.find('input[type="text"]').element as HTMLInputElement).value).toBe('203.0.113.7')
		expect(form.findAll('input[type="radio"]').find((input) => input.attributes('value') === '7')!.element).toHaveProperty('checked', true)
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
		expect(document.activeElement).toBe(wrapper.get('[data-test="incident-subject"]').element)
	})

	test('too many reports in a short time get their own message', async () => {
		const tooMany = Object.assign(new Error('Request failed with status code 429'), { isAxiosError: true, response: { status: 429, data: '' } })
		const wrapper = await mountTab(tooMany)
		expect(wrapper.text()).toContain('You built many reports in a short time. Try again in a few minutes.')
	})

	describe('picking from the list', () => {
		const A = { type: 'address' as const, value: '203.0.113.7', since: null, until: null }
		const B = { type: 'address' as const, value: '198.51.100.9', since: null, until: null }
		const reportA = report()
		const reportB = report({ subject: { type: 'address', value: '198.51.100.9', displayName: null } })

		beforeEach(() => {
			vi.mocked(fetchDetections).mockResolvedValue({
				detections: [detection({ id: 1, ip: A.value, lastSeenAt: AT }), detection({ id: 2, ip: B.value, lastSeenAt: AT - 60 })],
				hasMore: false,
			})
		})

		/**
		 * @param wrapper - The mounted tab
		 * @param index - 0 for A, 1 for B
		 */
		async function pick(wrapper: Awaited<ReturnType<typeof mountTab>>, index: number) {
			await wrapper.findAll('[data-test="incident-subject-item"]')[index]!.trigger('click')
			await flushPromises()
		}

		/**
		 * @param wrapper - The mounted tab
		 */
		async function downloadJson(wrapper: Awaited<ReturnType<typeof mountTab>>) {
			vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:report'), revokeObjectURL: vi.fn() }))
			vi.mocked(downloadIncidentReport).mockResolvedValue({ blob: new Blob(['{}']), filename: 'report.json' })
			await wrapper.get('[data-test="incident-download-json"]').trigger('click')
			await flushPromises()
			vi.unstubAllGlobals()
			return vi.mocked(downloadIncidentReport).mock.calls.at(-1)![0]
		}

		test('a cancelled password prompt keeps the shown report, and downloads stay with it', async () => {
			vi.mocked(buildIncidentReport).mockResolvedValueOnce(reportA)
			const wrapper = await mountTab()
			await pick(wrapper, 0)
			vi.mocked(buildIncidentReport).mockRejectedValueOnce(new PasswordConfirmationCancelledError())
			await pick(wrapper, 1)
			expect(wrapper.get('[data-test="incident-subject"]').text()).toBe('Address 203.0.113.7')
			expect(wrapper.findAll('[data-test="incident-subject-item"]')[0]!.attributes('aria-current')).toBe('true')
			expect(wrapper.text()).not.toContain('could not be built')
			expect(await downloadJson(wrapper)).toEqual(A)
		})

		test('only the answer to the latest pick is shown, whatever order the answers come in', async () => {
			let answerA: (value: IncidentReport) => void = () => {}
			let answerB: (value: IncidentReport) => void = () => {}
			vi.mocked(buildIncidentReport)
				.mockImplementationOnce(() => new Promise((resolve) => {
					answerA = resolve
				}))
				.mockImplementationOnce(() => new Promise((resolve) => {
					answerB = resolve
				}))
			const wrapper = await mountTab()
			await pick(wrapper, 0)
			await pick(wrapper, 1)
			answerB(reportB)
			await flushPromises()
			answerA(reportA)
			await flushPromises()
			expect(wrapper.get('[data-test="incident-subject"]').text()).toBe('Address 198.51.100.9')
			expect(await downloadJson(wrapper)).toEqual(B)
		})

		test('the shown report and recent ones are not built again', async () => {
			vi.mocked(buildIncidentReport).mockResolvedValueOnce(reportA).mockResolvedValueOnce(reportB)
			const wrapper = await mountTab()
			await pick(wrapper, 0)
			await pick(wrapper, 0)
			expect(buildIncidentReport).toHaveBeenCalledTimes(1)
			await pick(wrapper, 1)
			await pick(wrapper, 0)
			expect(buildIncidentReport).toHaveBeenCalledTimes(2)
			expect(wrapper.get('[data-test="incident-subject"]').text()).toBe('Address 203.0.113.7')
			expect(document.activeElement).toBe(wrapper.get('[data-test="incident-subject"]').element)
		})
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
