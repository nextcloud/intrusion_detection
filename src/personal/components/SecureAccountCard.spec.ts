/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import SecureAccountCard from './SecureAccountCard.vue'
import { fetchSecureAccountProgress } from '../../services/secureAccount.ts'

vi.mock('../../services/secureAccount.ts', () => ({
	fetchSecureAccountProgress: vi.fn(),
}))

enableAutoUnmount(afterEach)

/**
 * @param active - Whether a checklist is open
 * @param done - Steps done
 */
function account(active: boolean, done = 0) {
	return { active, done, total: 6, startedAt: 1, eventAt: 1, reason: 'denied', detectionId: 1, closedAt: null, closedBy: null, steps: [] }
}

describe('SecureAccountCard', () => {
	test('only the progress is loaded, not the whole checklist', async () => {
		vi.mocked(fetchSecureAccountProgress).mockClear().mockResolvedValue(account(true, 1) as never)
		mount(SecureAccountCard)
		await flushPromises()
		expect(fetchSecureAccountProgress).toHaveBeenCalledTimes(1)
	})

	test('an open checklist shows its progress and leads to the checklist page', async () => {
		vi.mocked(fetchSecureAccountProgress).mockResolvedValue(account(true, 2) as never)
		const wrapper = mount(SecureAccountCard)
		await flushPromises()
		expect(wrapper.get('[data-test="secure-account-progress"]').text()).toBe('2 of 6 steps done')
		expect(wrapper.get('progress').attributes('value')).toBe('2')
		const open = wrapper.get('[data-test="secure-account-open"]')
		expect(open.text()).toBe('Continue')
		expect(open.attributes('href')).toContain('/apps/intrusion_detection/secure-account')
	})

	test('a checklist without any step done offers to start', async () => {
		vi.mocked(fetchSecureAccountProgress).mockResolvedValue(account(true) as never)
		const wrapper = mount(SecureAccountCard)
		await flushPromises()
		expect(wrapper.get('[data-test="secure-account-open"]').text()).toBe('Start')
	})

	test('without an open checklist, or when it cannot be loaded, nothing is shown', async () => {
		vi.mocked(fetchSecureAccountProgress).mockResolvedValue(account(false) as never)
		const closed = mount(SecureAccountCard)
		await flushPromises()
		expect(closed.find('[data-test="secure-account"]').exists()).toBe(false)

		vi.mocked(fetchSecureAccountProgress).mockRejectedValue(new Error('offline'))
		const failed = mount(SecureAccountCard)
		await flushPromises()
		expect(failed.find('[data-test="secure-account"]').exists()).toBe(false)
	})
})
