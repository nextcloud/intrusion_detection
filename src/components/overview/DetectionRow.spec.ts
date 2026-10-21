/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import DetectionRow from './DetectionRow.vue'
import { setAdvanced } from '../../store.ts'
import { makeDetail } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDetection: vi.fn(() => new Promise(() => {})),
}))

describe('a detection in the list', () => {
	afterEach(() => {
		setAdvanced(false)
		window.localStorage.clear()
	})

	test('reads as one plain sentence, which also heads its detail', () => {
		const wrapper = mount(DetectionRow, { props: { detection: { ...makeDetail().detection, hits: 3 } } })
		expect(wrapper.get('[data-test="detection-summary"]').text()).toBe('Credential stuffing from 203.0.113.7. The address was blocked.')
		expect(wrapper.text()).toContain('3 times')
		expect(wrapper.text()).not.toContain('203.0.113.0/24')
	})

	test('the check, the address and the account are listed with the advanced options', async () => {
		const detection = { ...makeDetail().detection, uid: 'alice' }
		const wrapper = mount(DetectionRow, { props: { detection } })
		expect(wrapper.text()).not.toContain('account alice')
		setAdvanced(true)
		await flushPromises()
		expect(wrapper.text()).toContain('account alice')
		expect(wrapper.text()).toContain('Credential stuffing')
	})

	test('the sentence is shown as text, never as markup', () => {
		const wrapper = mount(DetectionRow, { props: { detection: { ...makeDetail().detection, summary: '<b>bold</b> summary' } } })
		expect(wrapper.find('b').exists()).toBe(false)
		expect(wrapper.text()).toContain('<b>bold</b> summary')
	})

	test('falls back to the check name for a detection without a summary', () => {
		const wrapper = mount(DetectionRow, { props: { detection: { ...makeDetail().detection, summary: '' } } })
		expect(wrapper.get('[data-test="detection-summary"]').text()).toBe('Credential stuffing')
	})
})
