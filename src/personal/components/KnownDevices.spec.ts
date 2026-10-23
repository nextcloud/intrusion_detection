/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { showError, showSuccess } from '@nextcloud/dialogs'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import KnownDevices from './KnownDevices.vue'
import { snowflake } from '../../tests/fixtures.ts'
import { knownDevice, overview } from '../../tests/personalFixtures.ts'
import { fetchKnownDevices, logOutElsewhere, removeKnownDevice } from '../api.ts'
import { logOutOtherBrowsers, personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchKnownDevices: vi.fn(),
	logOutElsewhere: vi.fn(),
	removeKnownDevice: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('KnownDevices', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.manage = { devices: 2, networks: 0, otherBrowsers: 0 }
	})

	afterEach(() => {
		vi.mocked(fetchKnownDevices).mockReset()
		vi.mocked(removeKnownDevice).mockReset()
		vi.mocked(showError).mockReset()
		vi.mocked(showSuccess).mockReset()
	})

	test('lists the devices with first and last use and marks this browser', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1, { current: true }), knownDevice(2, { label: 'Safari on iOS', platform: 'ios' })])
		const wrapper = mount(KnownDevices)
		expect(wrapper.find('[data-test="loading"]').exists()).toBe(true)
		await flushPromises()
		expect(wrapper.get(`[data-test="device-${snowflake(1)}"]`).text()).toContain('This browser')
		expect(wrapper.get(`[data-test="device-${snowflake(1)}"]`).text()).toContain('First used')
		expect(wrapper.get(`[data-test="device-${snowflake(1)}"]`).text()).toContain('Last used')
		expect(wrapper.get(`[data-test="device-${snowflake(2)}"]`).text()).not.toContain('This browser')
		expect(wrapper.get(`[data-test="device-${snowflake(2)}"] [data-test="remove-device"]`).attributes('aria-label')).toBe('Remove Safari on iOS')
	})

	test('removes a device', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1), knownDevice(2)])
		vi.mocked(removeKnownDevice).mockResolvedValue({ removed: snowflake(2) })
		const wrapper = mount(KnownDevices)
		await flushPromises()
		await wrapper.get(`[data-test="device-${snowflake(2)}"] [data-test="remove-device"]`).trigger('click')
		await flushPromises()
		expect(removeKnownDevice).toHaveBeenCalledWith(snowflake(2))
		expect(wrapper.find(`[data-test="device-${snowflake(2)}"]`).exists()).toBe(false)
		expect(showSuccess).toHaveBeenCalledWith('Firefox on Linux is no longer remembered.')
		expect(personal.manage.devices).toBe(1)
	})

	test('says what went wrong when removing fails', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1)])
		vi.mocked(removeKnownDevice).mockRejectedValue(new Error('offline'))
		const wrapper = mount(KnownDevices)
		await flushPromises()
		await wrapper.get('[data-test="remove-device"]').trigger('click')
		await flushPromises()
		expect(showError).toHaveBeenCalledWith('The device could not be removed. Please try again.')
		expect(wrapper.find(`[data-test="device-${snowflake(1)}"]`).exists()).toBe(true)
	})

	test('is left out without devices, and says when they could not be loaded after logging out elsewhere', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('offline'))
		vi.mocked(logOutElsewhere).mockResolvedValue({ sessions: 1, devices: 0 })
		const wrapper = mount(KnownDevices)
		await flushPromises()
		expect(wrapper.find('[data-test="known-devices"]').exists()).toBe(false)
		await logOutOtherBrowsers()
		await flushPromises()
		expect(fetchKnownDevices).toHaveBeenCalledTimes(2)
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('could not be loaded')
	})
})
