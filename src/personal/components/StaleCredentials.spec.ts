/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { StaleCredential } from '../types.ts'

import { showError, showSuccess } from '@nextcloud/dialogs'
import { PasswordConfirmationCancelledError } from '@nextcloud/password-confirmation'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import StaleCredentials from './StaleCredentials.vue'
import { NOW, overview } from '../../tests/personalFixtures.ts'
import { removeAllStaleCredentials, removeStaleCredential } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	removeStaleCredential: vi.fn(),
	removeAllStaleCredentials: vi.fn(),
}))

enableAutoUnmount(afterEach)

/**
 * @param id - The credential id
 * @param overrides - Fields to change
 */
function credential(id: number, overrides: Partial<StaleCredential> = {}): StaleCredential {
	return { id, name: 'Thunderbird', kind: 'app_password', lastUsed: NOW - 120 * 86400, ...overrides }
}

describe('StaleCredentials', () => {
	beforeEach(() => {
		personal.overview = overview()
	})

	afterEach(() => {
		personal.staleCredentials = []
		vi.mocked(removeStaleCredential).mockReset()
		vi.mocked(removeAllStaleCredentials).mockReset()
		vi.mocked(showError).mockReset()
		vi.mocked(showSuccess).mockReset()
		document.body.innerHTML = ''
	})

	test('is left out while there is nothing unused', () => {
		const wrapper = mount(StaleCredentials)
		expect(wrapper.find('[data-test="stale-credentials"]').exists()).toBe(false)
	})

	test('lists name, type and last use, with Remove for each and Remove all', () => {
		personal.staleCredentials = [credential(1), credential(2, { name: 'Firefox on Linux', kind: 'session' })]
		const wrapper = mount(StaleCredentials)
		expect(wrapper.text()).toContain('App passwords and devices you have not used for 3 months')
		expect(wrapper.get('[data-test="stale-1"]').text()).toContain('Thunderbird')
		expect(wrapper.get('[data-test="stale-1"]').text()).toContain('App password')
		expect(wrapper.get('[data-test="stale-1"]').text()).toContain('Last used')
		expect(wrapper.get('[data-test="stale-2"]').text()).toContain('Browser')
		expect(wrapper.get('[data-test="stale-2"] [data-test="remove-stale"]').attributes('aria-label')).toBe('Remove Firefox on Linux')
		expect(wrapper.find('[data-test="remove-all-stale"]').exists()).toBe(true)
	})

	test('offers no Remove all for a single one', () => {
		personal.staleCredentials = [credential(1)]
		const wrapper = mount(StaleCredentials)
		expect(wrapper.find('[data-test="remove-all-stale"]').exists()).toBe(false)
	})

	test('removes one and keeps the others', async () => {
		personal.staleCredentials = [credential(1), credential(2, { name: 'DAVx5' })]
		vi.mocked(removeStaleCredential).mockResolvedValue({ removed: 2 })
		const wrapper = mount(StaleCredentials)
		await wrapper.get('[data-test="stale-2"] [data-test="remove-stale"]').trigger('click')
		await flushPromises()
		expect(removeStaleCredential).toHaveBeenCalledWith(2)
		expect(wrapper.find('[data-test="stale-2"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="stale-1"]').exists()).toBe(true)
		expect(showSuccess).toHaveBeenCalledWith('DAVx5 was removed.')
	})

	test('keeps the list when the password dialog was closed, and says when removing failed', async () => {
		personal.staleCredentials = [credential(1)]
		vi.mocked(removeStaleCredential).mockRejectedValueOnce(new PasswordConfirmationCancelledError()).mockRejectedValueOnce(new Error('offline'))
		const wrapper = mount(StaleCredentials)
		await wrapper.get('[data-test="remove-stale"]').trigger('click')
		await flushPromises()
		expect(showError).not.toHaveBeenCalled()
		await wrapper.get('[data-test="remove-stale"]').trigger('click')
		await flushPromises()
		expect(showError).toHaveBeenCalledWith('It could not be removed. Please try again.')
		expect(wrapper.find('[data-test="stale-1"]').exists()).toBe(true)
	})

	test('removes all after the confirmation', async () => {
		personal.staleCredentials = [credential(1), credential(2)]
		vi.mocked(removeAllStaleCredentials).mockResolvedValue({ removed: 2 })
		const wrapper = mount(StaleCredentials, { attachTo: document.body })
		await wrapper.get('[data-test="remove-all-stale"]').trigger('click')
		await flushPromises()
		expect(removeAllStaleCredentials).not.toHaveBeenCalled()
		const button = [...document.body.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent?.trim() === 'Remove all') as HTMLButtonElement
		button.click()
		await flushPromises()
		expect(removeAllStaleCredentials).toHaveBeenCalledOnce()
		expect(personal.staleCredentials).toEqual([])
		expect(showSuccess).toHaveBeenCalledWith('2 unused app passwords and devices were removed.')
		expect(wrapper.find('[data-test="stale-credentials"]').exists()).toBe(false)
	})
})
