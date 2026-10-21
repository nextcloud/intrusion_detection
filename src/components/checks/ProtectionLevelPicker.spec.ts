/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import ProtectionLevelPicker from './ProtectionLevelPicker.vue'
import { ApiError, fetchSettings, updateProtectionLevel } from '../../services/api.ts'
import { state } from '../../store.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateProtectionLevel: vi.fn(),
	fetchSettings: vi.fn(),
}))

const radios = (wrapper: ReturnType<typeof mount>) => wrapper.findAll('input[type="radio"]')
const labels = (wrapper: ReturnType<typeof mount>) => radios(wrapper).map((radio) => radio.element.parentElement?.textContent?.trim())

describe('the protection level', () => {
	beforeEach(() => {
		state.protectionLevel = 'recommended'
		state.checks = [makeCheck()]
		vi.mocked(fetchSettings).mockResolvedValue({ settings: [], templates: {} })
	})

	afterEach(() => {
		vi.mocked(updateProtectionLevel).mockReset()
		document.body.innerHTML = ''
	})

	test('offers Relaxed, Recommended and Strict, from the loosest to the tightest, and explains the chosen one', () => {
		const wrapper = mount(ProtectionLevelPicker)
		expect(labels(wrapper)).toEqual(['Relaxed', 'Recommended', 'Strict'])
		expect((radios(wrapper)[1]!.element as HTMLInputElement).checked).toBe(true)
		expect(wrapper.text()).toContain('Balanced limits that suit most servers.')
		expect(wrapper.text()).toContain('Modes and responses stay as they are.')
	})

	test('"Custom" is shown, and cannot be chosen, after a change by hand', () => {
		state.protectionLevel = 'custom'
		const wrapper = mount(ProtectionLevelPicker)
		expect(labels(wrapper)).toEqual(['Relaxed', 'Recommended', 'Strict', 'Custom'])
		const custom = radios(wrapper)[3]!.element as HTMLInputElement
		expect(custom.checked).toBe(true)
		expect(custom.disabled).toBe(true)
		expect(wrapper.text()).toContain('Some limits were changed by hand.')
	})

	test('one click sets every limit and loads the checks and settings the server returns', async () => {
		const strict = makeCheck({ params: makeCheck().params.map((p) => p.name === 'min_failures' ? { ...p, value: 5 } : p) })
		vi.mocked(updateProtectionLevel).mockResolvedValue({ level: 'strict', checks: { checks: [strict], categories: [] } })
		const wrapper = mount(ProtectionLevelPicker)
		await radios(wrapper)[2]!.setValue(true)
		await radios(wrapper)[2]!.trigger('change')
		await flushPromises()
		expect(updateProtectionLevel).toHaveBeenCalledTimes(1)
		expect(updateProtectionLevel).toHaveBeenCalledWith('strict')
		expect(state.protectionLevel).toBe('strict')
		expect(state.checks[0]!.params.find((p) => p.name === 'min_failures')!.value).toBe(5)
		expect(fetchSettings).toHaveBeenCalled()
	})

	test('a refused change keeps the level', async () => {
		vi.mocked(updateProtectionLevel).mockRejectedValue(new ApiError('Nope'))
		const wrapper = mount(ProtectionLevelPicker)
		await radios(wrapper)[0]!.setValue(true)
		await radios(wrapper)[0]!.trigger('change')
		await flushPromises()
		expect(state.protectionLevel).toBe('recommended')
	})
})
