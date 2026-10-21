/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import SecurityChanges from './SecurityChanges.vue'
import { fetchSecurityChanges } from '../../services/secureAccount.ts'

vi.mock('../../services/secureAccount.ts', () => ({
	fetchSecurityChanges: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('SecurityChanges', () => {
	test('each change says what changed, from what, by whom and from where', async () => {
		vi.mocked(fetchSecurityChanges).mockResolvedValue([
			{ id: 1, type: 'email_changed', label: 'Email address changed', via: 'self', actor: 'alice', previous: 'a***@example.com', new: 'b***@example.org', detail: null, address: '203.0.113.7', createdAt: 1_800_000_000 },
			{ id: 2, type: 'password_changed', label: 'Password changed', via: 'reset', actor: null, previous: null, new: null, detail: null, address: null, createdAt: 1_799_990_000 },
		])
		const wrapper = mount(SecurityChanges)
		await flushPromises()
		const first = wrapper.get('[data-test="change-1"]').text()
		expect(first).toContain('Email address changed')
		expect(first).toContain('from a***@example.com to b***@example.org')
		expect(first).toContain('by you')
		expect(first).toContain('from 203.0.113.7')
		expect(wrapper.get('[data-test="change-2"]').text()).toContain('through a password reset')
		expect(fetchSecurityChanges).toHaveBeenCalledWith(20)
	})

	test('an empty list says so', async () => {
		vi.mocked(fetchSecurityChanges).mockResolvedValue([])
		const wrapper = mount(SecurityChanges)
		await flushPromises()
		expect(wrapper.text()).toContain('No security changes recently.')
	})

	test('a failure offers to try again', async () => {
		vi.mocked(fetchSecurityChanges).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([])
		const wrapper = mount(SecurityChanges)
		await flushPromises()
		expect(wrapper.text()).toContain('could not be loaded')
		await wrapper.get('button').trigger('click')
		await flushPromises()
		expect(wrapper.text()).toContain('No security changes recently.')
	})
})
