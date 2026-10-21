/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting } from '../types.ts'

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import MasterSwitch from './MasterSwitch.vue'
import { updateSettings } from '../services/api.ts'
import { state } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))
vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateSettings: vi.fn(),
	fetchStatus: vi.fn(() => Promise.resolve(makeStatus())),
	fetchChecks: vi.fn(() => Promise.resolve({ checks: [], categories: [] })),
}))

/**
 * @param value - Whether intrusion detection is on
 */
function master(value: boolean): GlobalSetting {
	return { name: 'protection_enabled', type: 'bool', default: true, min: null, max: null, choices: [], value, label: 'On', help: '', unit: '', group: 'master' }
}

enableAutoUnmount(afterEach)

describe('the master switch', () => {
	beforeEach(() => {
		state.status = makeStatus()
		state.settings = [master(true)]
	})

	afterEach(() => {
		vi.mocked(updateSettings).mockReset()
		document.body.innerHTML = ''
	})

	const input = (wrapper: ReturnType<typeof mount>) => wrapper.get('input[type="checkbox"]')

	test('shows whether intrusion detection is on', () => {
		expect((input(mount(MasterSwitch)).element as HTMLInputElement).checked).toBe(true)
		state.settings = [master(false)]
		expect((input(mount(MasterSwitch)).element as HTMLInputElement).checked).toBe(false)
	})

	test('turning it off asks first and changes nothing until confirmed', async () => {
		const wrapper = mount(MasterSwitch, { attachTo: document.body })
		await input(wrapper).trigger('click')
		await flushPromises()
		expect(document.body.textContent).toContain('Turn off intrusion detection?')
		expect(updateSettings).not.toHaveBeenCalled()
	})

	test('turning it on needs no confirmation', async () => {
		state.settings = [master(false)]
		vi.mocked(updateSettings).mockResolvedValue({ settings: [master(true)], templates: {} })
		const wrapper = mount(MasterSwitch, { attachTo: document.body })
		await input(wrapper).trigger('click')
		await flushPromises()
		expect(updateSettings).toHaveBeenCalledWith({ protection_enabled: true })
		expect(state.settings[0]!.value).toBe(true)
	})
})
