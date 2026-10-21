/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import DetectionNarrative from './DetectionNarrative.vue'
import { incidentRequest } from '../../store.ts'
import { makeDetail } from '../../tests/fixtures.ts'

/**
 * @param text - The button's text
 * @param wrapper - The mounted component
 */
function button(wrapper: ReturnType<typeof mount>, text: string) {
	return wrapper.findAll('button').find((b) => b.text() === text)
}

describe('DetectionNarrative', () => {
	test('tells what happened and what Nextcloud did', () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		expect(wrapper.text()).toContain('Why did this happen?')
		expect(wrapper.text()).toContain('failed to log in 14 times, trying 9 different accounts')
		expect(wrapper.text()).toContain('What Nextcloud did')
		expect(wrapper.text()).toContain('Blocked 203.0.113.7/32 until 14:09')
		expect(wrapper.text()).toContain('K7Q2-MPXA')
	})

	test('observed detections say what would have happened, and why nothing did', () => {
		const detail = makeDetail({
			bans: [],
			narrative: {
				title: 'Credential stuffing',
				happened: ['The address 203.0.113.7 failed to log in 14 times.'],
				done: ['Would have: Block the address for hours, longer if it comes back.'],
				observedBecause: 'Nothing was done, because learning mode was on: Nextcloud was watching, not acting.',
			},
		})
		detail.detection.enforced = false
		const wrapper = mount(DetectionNarrative, { props: { detail } })
		expect(wrapper.text()).toContain('What Nextcloud would have done')
		expect(wrapper.text()).toContain('Would have: Block the address')
		expect(wrapper.text()).toContain('because learning mode was on')
		expect(button(wrapper, 'Lift block')).toBeUndefined()
	})

	test('"Lift block" asks the parent to lift the active block', async () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		await button(wrapper, 'Lift block')!.trigger('click')
		expect(wrapper.emitted('lift')?.[0]?.[0]).toMatchObject({ id: 7, reference: 'K7Q2-MPXA' })
	})

	test('"Show attempts" lists the attempts of the last hour', async () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		expect(wrapper.find('table').exists()).toBe(false)
		await button(wrapper, 'Show attempts')!.trigger('click')
		const rows = wrapper.findAll('tbody tr')
		expect(rows).toHaveLength(1)
		expect(rows[0]!.text()).toContain('Failed password login')
		expect(rows[0]!.text()).toContain('alice')
	})

	test('older detections explain that attempts are not kept', async () => {
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail({ attemptsAvailable: false, attempts: [] }) } })
		await button(wrapper, 'Show attempts')!.trigger('click')
		expect(wrapper.text()).toContain('Details older than 1 hour are not kept')
	})

	test('"Copy as text" copies the plain text narrative', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined)
		Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
		const wrapper = mount(DetectionNarrative, { props: { detail: makeDetail() } })
		await button(wrapper, 'Copy as text')!.trigger('click')
		expect(writeText).toHaveBeenCalledWith('Credential stuffing\n\nBetween 10:02 and 10:09 …')
	})

	test('texts from the server are shown as text, never as markup', () => {
		const detail = makeDetail()
		detail.narrative.happened = ['<img src=x onerror=alert(1)> tried']
		const wrapper = mount(DetectionNarrative, { props: { detail } })
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
})
