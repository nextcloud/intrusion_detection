/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import DetectionNarrative from './DetectionNarrative.vue'
import { incidentRequest } from '../../store.ts'
import { makeDetail, snowflake } from '../../tests/fixtures.ts'

/**
 * @param text - The button's text
 * @param wrapper - The mounted component
 */
function button(wrapper: ReturnType<typeof mount>, text: string) {
	return wrapper.findAll('button').find((b) => b.text() === text)
}

/**
 * Mount the detail with "Details" open.
 *
 * @param props - The props
 * @param props.detail - The detection detail
 * @param options - More mount options
 */
async function mountOpen(props: { detail: ReturnType<typeof makeDetail> }, options: Parameters<typeof mount>[1] = {}) {
	const wrapper = mount(DetectionNarrative, { props, ...options })
	await wrapper.get('[data-test="show-details"]').trigger('click')
	return wrapper
}

describe('DetectionNarrative', () => {
	test('below the plain sentence of its row, the detail starts with the actions; the narrative is under "Details"', async () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		expect(wrapper.text()).not.toContain('Why did this happen?')
		expect(wrapper.find('[data-test="show-attempts"]').exists()).toBe(false)
		expect(button(wrapper, 'Lift block')).toBeDefined()
		const details = wrapper.get('[data-test="show-details"]')
		expect(details.attributes('aria-expanded')).toBe('false')
		await details.trigger('click')
		expect(details.attributes('aria-expanded')).toBe('true')
		expect(wrapper.get('[data-test="detection-details"]').text()).toContain('Why did this happen?')
	})

	test('tells what happened and what Nextcloud did', async () => {
		const wrapper = await mountOpen({ detail: makeDetail() })
		expect(wrapper.text()).toContain('Why did this happen?')
		expect(wrapper.text()).toContain('failed to log in 14 times, trying 9 different accounts')
		expect(wrapper.text()).toContain('What Nextcloud did')
		expect(wrapper.text()).toContain('Blocked 203.0.113.7/32 until 14:09')
		expect(wrapper.text()).toContain('K7Q2-MPXA')
	})

	test('observed detections say what would have happened, and why nothing did', async () => {
		const detail = makeDetail({
			bans: [],
			narrative: {
				title: 'Credential stuffing',
				happened: ['The address 203.0.113.7 failed to log in 14 times.'],
				done: ['Block the address for hours, longer if it comes back.'],
				observedBecause: 'Nothing was done, because learning mode was on.',
			},
		})
		detail.detection.enforced = false
		const wrapper = await mountOpen({ detail })
		expect(wrapper.text()).toContain('What Nextcloud would have done')
		expect(wrapper.text()).toContain('Block the address')
		expect(wrapper.text()).not.toContain('Would have:')
		expect(wrapper.text()).toContain('because learning mode was on')
		expect(button(wrapper, 'Lift block')).toBeUndefined()
	})

	test('"Lift block" asks the parent to lift the active block', async () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		await button(wrapper, 'Lift block')!.trigger('click')
		expect(wrapper.emitted('lift')?.[0]?.[0]).toMatchObject({ id: snowflake(7), reference: 'K7Q2-MPXA' })
	})

	test('"Show attempts" lists the attempts of the last hour', async () => {
		const wrapper = await mountOpen({ detail: makeDetail() })
		expect(wrapper.find('table').exists()).toBe(false)
		await button(wrapper, 'Show attempts')!.trigger('click')
		const rows = wrapper.findAll('tbody tr')
		expect(rows).toHaveLength(1)
		expect(rows[0]!.text()).toContain('Failed password login')
		expect(rows[0]!.text()).toContain('alice')
	})

	test('older detections explain that attempts are not kept', async () => {
		const wrapper = await mountOpen({ detail: makeDetail({ attemptsAvailable: false, attempts: [] }) })
		await button(wrapper, 'Show attempts')!.trigger('click')
		expect(wrapper.text()).toContain('Details older than 1 hour are not kept')
	})

	test('"Copy as text" copies the plain text narrative', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined)
		Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
		const wrapper = await mountOpen({ detail: makeDetail() })
		await button(wrapper, 'Copy as text')!.trigger('click')
		expect(writeText).toHaveBeenCalledWith('Credential stuffing\n\nBetween 10:02 and 10:09 …')
	})

	test('texts from the server are shown as text, never as markup', async () => {
		const detail = makeDetail()
		detail.narrative.happened = ['<img src=x onerror=alert(1)> tried']
		const wrapper = await mountOpen({ detail })
		expect(wrapper.find('img').exists()).toBe(false)
		expect(wrapper.text()).toContain('<img src=x onerror=alert(1)> tried')
	})

	test('"Incident report" opens the Incidents tab with the account or the address', async () => {
		const showTab = vi.fn()
		const detail = makeDetail()
		detail.detection.uid = 'alice'
		const wrapper = mount(DetectionNarrative, { props: { detail }, global: { provide: { 'ids-show-tab': showTab } } })
		await wrapper.get('[data-test="incident-report-address"]').trigger('click')
		expect(incidentRequest.value).toEqual({ type: 'address', value: detail.detection.ip, since: null, until: null })
		expect(showTab).toHaveBeenCalledWith('incidents')
		await wrapper.get('[data-test="incident-report-user"]').trigger('click')
		expect(incidentRequest.value).toEqual({ type: 'user', value: 'alice', since: null, until: null })
		incidentRequest.value = null

		detail.detection.uid = null
		detail.detection.ip = null
		const without = mount(DetectionNarrative, { props: { detail } })
		expect(without.find('[data-test^="incident-report-"]').exists()).toBe(false)
	})

	test('offers the attempts only for a detection with an address', async () => {
		expect((await mountOpen({ detail: makeDetail() })).find('[data-test="show-attempts"]').exists()).toBe(true)
		const detail = makeDetail()
		detail.detection.ip = null
		detail.detection.checkId = 'admin_change'
		expect((await mountOpen({ detail })).find('[data-test="show-attempts"]').exists()).toBe(false)
	})
})
