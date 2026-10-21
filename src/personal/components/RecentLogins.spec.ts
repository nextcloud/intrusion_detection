/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import RecentLogins from './RecentLogins.vue'
import { login, overview } from '../../tests/personalFixtures.ts'
import { fetchLogins } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchLogins: vi.fn(),
}))

enableAutoUnmount(afterEach)

describe('RecentLogins', () => {
	beforeEach(() => {
		personal.overview = overview()
	})

	afterEach(() => {
		vi.mocked(fetchLogins).mockReset()
	})

	test('loads the last 30 days', async () => {
		vi.mocked(fetchLogins).mockReturnValue(new Promise(() => {}))
		const wrapper = mount(RecentLogins)
		expect(fetchLogins).toHaveBeenCalledWith(30)
		expect(wrapper.find('[data-test="loading"]').exists()).toBe(true)
	})

	test('shows time, address, device, method and confirmation of each login', async () => {
		vi.mocked(fetchLogins).mockResolvedValue([
			login(1, { current: true }),
			login(2, { method: 'app_password', userAgent: 'Mozilla/5.0 (Android) Nextcloud-android/3.30', device: 'Nextcloud Android app on Android' }),
			login(3, { knownDevice: true, confirmedBy: 'known_device', stepUp: 'confirmed' }),
			login(4, { confirmedBy: 'email_code', stepUp: 'confirmed' }),
			login(5, { stepUp: 'refused' }),
		])
		const wrapper = mount(RecentLogins)
		await flushPromises()
		const first = wrapper.get('[data-test="login-1"]').text()
		expect(first).toContain('Firefox on Linux')
		expect(first).toContain('This session')
		expect(first).toContain('198.51.100.1')
		expect(first).toContain('Password')
		expect(first).toContain('No extra confirmation needed')
		expect(wrapper.get('[data-test="login-2"]').text()).toContain('App password')
		expect(wrapper.get('[data-test="login-3"]').text()).toContain('Remembered device')
		expect(wrapper.get('[data-test="login-3"]').text()).toContain('Confirmed by a remembered device')
		expect(wrapper.get('[data-test="login-4"]').text()).toContain('Confirmed with an email code')
		expect(wrapper.get('[data-test="login-5"]').text()).toContain('Refused')
	})

	test('says so when there were none', async () => {
		vi.mocked(fetchLogins).mockResolvedValue([])
		const wrapper = mount(RecentLogins)
		await flushPromises()
		expect(wrapper.get('[data-test="empty"]').text()).toBe('No logins in the last 30 days.')
	})

	test('explains a failure and loads again on request', async () => {
		vi.mocked(fetchLogins).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([login(1)])
		const wrapper = mount(RecentLogins)
		await flushPromises()
		expect(wrapper.get('[data-test="load-error"]').text()).toContain('Your recent logins could not be loaded')
		await wrapper.get('[data-test="load-error"] button').trigger('click')
		await flushPromises()
		expect(wrapper.find('[data-test="login-1"]').exists()).toBe(true)
	})

	test('shows the newest and the rest on request', async () => {
		vi.mocked(fetchLogins).mockResolvedValue(Array.from({ length: 9 }, (_, i) => login(i + 1)))
		const wrapper = mount(RecentLogins)
		await flushPromises()
		expect(wrapper.findAll('[data-test^="login-"]')).toHaveLength(6)
		await wrapper.findAll('button').find((b) => b.text() === 'Show all 9 logins')!.trigger('click')
		expect(wrapper.findAll('[data-test^="login-"]')).toHaveLength(9)
	})
})
