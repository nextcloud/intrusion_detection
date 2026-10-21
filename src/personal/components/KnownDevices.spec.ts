/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { showError, showSuccess } from '@nextcloud/dialogs'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import KnownDevices from './KnownDevices.vue'
import { knownDevice, overview } from '../../tests/personalFixtures.ts'
import { fetchKnownDevices, removeKnownDevice } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchKnownDevices: vi.fn(),
	removeKnownDevice: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('KnownDevices', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.knownDevicesEnabled = true
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
		expect(wrapper.get('[data-test="device-1"]').text()).toContain('This browser')
		expect(wrapper.get('[data-test="device-1"]').text()).toContain('First used')
		expect(wrapper.get('[data-test="device-1"]').text()).toContain('Last used')
		expect(wrapper.get('[data-test="device-2"]').text()).not.toContain('This browser')
		expect(wrapper.get('[data-test="device-2"] [data-test="remove-device"]').attributes('aria-label')).toBe('Remove Safari on iOS')
	})

	test('removes a device', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1), knownDevice(2)])
		vi.mocked(removeKnownDevice).mockResolvedValue({ removed: 2 })
		const wrapper = mount(KnownDevices)
		await flushPromises()
		await wrapper.get('[data-test="device-2"] [data-test="remove-device"]').trigger('click')
		await flushPromises()
		expect(removeKnownDevice).toHaveBeenCalledWith(2)
		expect(wrapper.find('[data-test="device-2"]').exists()).toBe(false)
		expect(showSuccess).toHaveBeenCalledWith('Firefox on Linux is no longer remembered.')
	})

	test('says what went wrong when removing fails', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1)])
		vi.mocked(removeKnownDevice).mockRejectedValue(new Error('offline'))
		const wrapper = mount(KnownDevices)
		await flushPromises()
		await wrapper.get('[data-test="remove-device"]').trigger('click')
		await flushPromises()
		expect(showError).toHaveBeenCalledWith('The device could not be removed. Please try again.')
		expect(wrapper.find('[data-test="device-1"]').exists()).toBe(true)
	})

	test('has an empty state and an error state', async () => {
		vi.mocked(fetchKnownDevices).mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('offline'))
		const wrapper = mount(KnownDevices)
		await flushPromises()
		expect(wrapper.get('[data-test="empty"]').text()).toContain('No remembered devices')
		personal.devicesVersion++
		await nextTick()
		await flushPromises()
		expect(fetchKnownDevices).toHaveBeenCalledTimes(2)
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('could not be loaded')
	})

	test('is hidden when devices cannot be remembered and none are', async () => {
		personal.knownDevicesEnabled = false
		vi.mocked(fetchKnownDevices).mockResolvedValue([])
		const wrapper = mount(KnownDevices)
		await flushPromises()
		expect(wrapper.find('[data-test="known-devices"]').exists()).toBe(false)
	})
})
