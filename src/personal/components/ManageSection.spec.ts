/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import ManageSection from './ManageSection.vue'
import { snowflake } from '../../tests/fixtures.ts'
import { knownDevice, overview } from '../../tests/personalFixtures.ts'
import { fetchKnownDevices, fetchTrustedNetworks, removeKnownDevice } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchKnownDevices: vi.fn(),
	fetchTrustedNetworks: vi.fn(),
	removeKnownDevice: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('ManageSection', () => {
	beforeEach(() => {
		personal.overview = overview()
		vi.mocked(fetchKnownDevices).mockResolvedValue([knownDevice(1)])
		vi.mocked(fetchTrustedNetworks).mockResolvedValue([])
	})

	afterEach(() => {
		vi.mocked(fetchKnownDevices).mockReset()
		vi.mocked(fetchTrustedNetworks).mockReset()
		vi.mocked(removeKnownDevice).mockReset()
	})

	test('is collapsed, says what it holds and loads nothing until opened', async () => {
		personal.manage = { devices: 2, networks: 1, otherBrowsers: 3 }
		const wrapper = mount(ManageSection)

		const toggle = wrapper.get('[data-test="manage"] button')
		expect(toggle.attributes('aria-expanded')).toBe('false')
		expect(toggle.text()).toContain('Manage')
		expect(toggle.text()).toContain('2 remembered devices · 1 trusted network · 3 other browsers')
		expect(fetchKnownDevices).not.toHaveBeenCalled()

		await toggle.trigger('click')
		await flushPromises()
		expect(toggle.attributes('aria-expanded')).toBe('true')
		expect(fetchKnownDevices).toHaveBeenCalled()
		expect(wrapper.find('[data-test="known-devices"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="log-out-elsewhere"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="trusted-networks"]').exists(), 'Its list came back empty').toBe(false)
	})

	test('holds only what the account has', async () => {
		personal.manage = { devices: 1, networks: 0, otherBrowsers: 0 }
		const wrapper = mount(ManageSection)
		await wrapper.get('[data-test="manage"] button').trigger('click')
		await flushPromises()

		expect(wrapper.get('[data-test="manage"] button').text()).toContain('1 remembered device')
		expect(wrapper.find('[data-test="known-devices"]').exists()).toBe(true)
		expect(fetchTrustedNetworks).not.toHaveBeenCalled()
		expect(wrapper.find('[data-test="log-out-elsewhere"]').exists()).toBe(false)
	})

	test('stays while the user empties it', async () => {
		personal.manage = { devices: 1, networks: 0, otherBrowsers: 0 }
		vi.mocked(removeKnownDevice).mockResolvedValue({ removed: snowflake(1) })
		const wrapper = mount(ManageSection)
		await wrapper.get('[data-test="manage"] button').trigger('click')
		await flushPromises()

		await wrapper.get('[data-test="remove-device"]').trigger('click')
		await flushPromises()
		await nextTick()

		expect(personal.manage.devices).toBe(0)
		expect(wrapper.find('[data-test="manage"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="known-devices"]').exists()).toBe(false)
	})

	test('is left out, heading and all, when the account has nothing to manage', () => {
		personal.manage = { devices: 0, networks: 0, otherBrowsers: 0 }
		expect(mount(ManageSection).html()).toBe('<!--v-if-->')
	})
})
