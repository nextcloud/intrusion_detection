/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { showSuccess } from '@nextcloud/dialogs'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import TrustedNetworks from './TrustedNetworks.vue'
import { overview, trustedNetwork } from '../../tests/personalFixtures.ts'
import { fetchTrustedNetworks, removeTrustedNetwork } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchTrustedNetworks: vi.fn(),
	removeTrustedNetwork: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('TrustedNetworks', () => {
	beforeEach(() => {
		personal.overview = overview({ timezone: 'UTC' })
	})

	afterEach(() => {
		vi.mocked(fetchTrustedNetworks).mockReset()
		vi.mocked(removeTrustedNetwork).mockReset()
		vi.mocked(showSuccess).mockReset()
	})

	test('lists the networks with since and until, and removes one', async () => {
		vi.mocked(fetchTrustedNetworks).mockResolvedValue([trustedNetwork(4)])
		vi.mocked(removeTrustedNetwork).mockResolvedValue({ removed: 4 })
		const wrapper = mount(TrustedNetworks)
		await flushPromises()
		const row = wrapper.get('[data-test="network-4"]')
		expect(row.text()).toContain('203.0.113.0/24')
		expect(row.text()).toContain('Trusted since October 20, 2026, until November 19, 2026')
		await row.get('[data-test="remove-network"]').trigger('click')
		await flushPromises()
		expect(removeTrustedNetwork).toHaveBeenCalledWith(4)
		expect(showSuccess).toHaveBeenCalledWith('The network 203.0.113.0/24 is no longer trusted.')
		expect(wrapper.get('[data-test="empty"]').text()).toContain('No trusted networks. When you answer "Yes, it was me"')
	})

	test('loads again after an answer elsewhere on the page', async () => {
		vi.mocked(fetchTrustedNetworks).mockResolvedValueOnce([]).mockResolvedValueOnce([trustedNetwork(5)])
		const wrapper = mount(TrustedNetworks)
		await flushPromises()
		personal.networksVersion++
		await nextTick()
		await flushPromises()
		expect(wrapper.find('[data-test="network-5"]').exists()).toBe(true)
	})

	test('explains a failure', async () => {
		vi.mocked(fetchTrustedNetworks).mockRejectedValue(new Error('offline'))
		const wrapper = mount(TrustedNetworks)
		expect(wrapper.find('[data-test="loading"]').exists()).toBe(true)
		await flushPromises()
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('Your trusted networks could not be loaded')
	})
})
