/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import PersonalSettings from './PersonalSettings.vue'
import { fetchActivity } from '../personal/api.ts'
import { personal } from '../personal/store.ts'
import { activity, activityItem, login, overview, securityEvent } from '../tests/personalFixtures.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../personal/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchActivity: vi.fn(),
	fetchKnownDevices: vi.fn(() => Promise.resolve([])),
	fetchTrustedNetworks: vi.fn(() => Promise.resolve([])),
}))

vi.mock('../services/secureAccount.ts', () => ({
	fetchSecureAccountProgress: vi.fn(() => Promise.resolve({ active: false })),
}))

/**
 * Mount the page once its sections are loaded.
 */
async function mountPage() {
	const wrapper = mount(PersonalSettings)
	for (let i = 0; i < 5; i++) {
		await flushPromises()
		await vi.dynamicImportSettled()
	}
	return wrapper
}

/**
 * The sections that show something, in their order.
 *
 * @param wrapper - The page
 */
function shownSections(wrapper: Awaited<ReturnType<typeof mountPage>>): string[] {
	return wrapper.findAll('[data-section]').filter((s) => s.element.children.length > 0).map((s) => s.attributes('data-section')!)
}

enableAutoUnmount(afterEach)

describe('PersonalSettings', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.activity = null
		personal.manage = { devices: 0, networks: 0, otherBrowsers: 0 }
	})

	afterEach(() => {
		vi.mocked(fetchActivity).mockReset()
	})

	test('a brand-new account sees just the status line', async () => {
		vi.mocked(fetchActivity).mockResolvedValue(activity({ items: [activityItem({ login: login(1, { current: true }) })] }))
		const wrapper = await mountPage()

		expect(fetchActivity).toHaveBeenCalledTimes(1)
		expect(wrapper.find('h2').text()).toBe('Account protection')
		expect(shownSections(wrapper)).toEqual(['status'])
		expect(wrapper.findAll('h3').map((h) => h.text())).toEqual(['No unusual activity in the last 30 days'])
	})

	test('and the email hint when Nextcloud has no way to confirm it is them', async () => {
		personal.overview = overview({ emailHint: { emailUrl: '/settings/user', secondFactorUrl: null } })
		vi.mocked(fetchActivity).mockResolvedValue(activity())
		const wrapper = await mountPage()

		expect(shownSections(wrapper)).toEqual(['status', 'email-hint'])
	})

	test('a busy account sees the open questions, the timeline and "Manage", in this order', async () => {
		personal.manage = { devices: 1, networks: 0, otherBrowsers: 0 }
		vi.mocked(fetchActivity).mockResolvedValue(activity({
			questions: [securityEvent(1, { asks: true })],
			items: [activityItem({ login: login(2) })],
		}))
		const wrapper = await mountPage()

		expect(shownSections(wrapper)).toEqual(['status', 'questions', 'activity', 'manage'])
		expect(wrapper.findAll('[data-section]').map((s) => s.attributes('data-section'))[0], 'The checklist card has the top').toBe('secure-account')
	})

	test('sections with nothing to show take no room', async () => {
		vi.mocked(fetchActivity).mockResolvedValue(activity())
		const wrapper = await mountPage()

		for (const id of ['secure-account', 'email-hint', 'questions', 'activity', 'manage']) {
			expect(wrapper.get(`[data-section="${id}"]`).element.children, id).toHaveLength(0)
		}
	})
})
