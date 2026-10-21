/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Notifications } from '../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import NotificationsTab from './NotificationsTab.vue'
import { fetchNotifications } from '../services/api.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchNotifications: vi.fn(),
	fetchChecks: vi.fn(() => new Promise(() => {})),
}))

/**
 * @param overrides - Fields to change
 */
function notifications(overrides: Partial<Notifications> = {}): Notifications {
	return {
		recipients: [
			{ uid: 'admin', displayName: 'Admin', hasEmail: true },
			{ uid: 'bob', displayName: 'Bob', hasEmail: false },
		],
		recipientLimit: 50,
		mail: false,
		me: { uid: 'admin', email: 'admin@example.com', recipient: true },
		checks: [
			{ id: 'credential_stuffing', name: 'Credential stuffing', category: 'login_attacks', mode: 'protect', admin: true, user: false, adminAvailable: true, userAvailable: true },
		],
		...overrides,
	}
}

/**
 * @param value - What the API returns
 */
async function mountTab(value = notifications()) {
	vi.mocked(fetchNotifications).mockResolvedValue(value)
	const wrapper = mount(NotificationsTab, { global: { stubs: { NcSettingsSelectGroup: true, NcAvatar: true } } })
	await flushPromises()
	return wrapper
}

describe('the Notifications tab', () => {
	afterEach(() => {
		vi.mocked(fetchNotifications).mockReset()
	})

	test('says once that the server cannot send emails', async () => {
		const wrapper = await mountTab()
		expect(wrapper.findAll('[data-test="no-mail"]')).toHaveLength(1)
		expect(wrapper.text().match(/cannot send emails/g)).toHaveLength(1)
		expect(wrapper.text()).not.toContain('of them has no email address')
	})

	test('marks the people without an email address in the list, and says nothing when mail works', async () => {
		const wrapper = await mountTab(notifications({ mail: true }))
		expect(wrapper.find('[data-test="no-mail"]').exists()).toBe(false)
		expect(wrapper.text()).toContain('no email')
	})

	test('names both columns of the table the same way', async () => {
		const wrapper = await mountTab()
		const row = wrapper.get('tbody tr').text()
		expect(row).toContain('Notified')
		expect(row).toContain('Not notified')
		expect(row).not.toContain('Told')
	})
})
