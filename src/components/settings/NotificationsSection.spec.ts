/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Notifications } from '../../types.ts'

import { showSuccess, showWarning } from '@nextcloud/dialogs'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import NotificationsSection from './NotificationsSection.vue'
import { fetchNotifications, sendTestAlert } from '../../services/api.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn(), showWarning: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchNotifications: vi.fn(),
	sendTestAlert: vi.fn(),
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
	const wrapper = mount(NotificationsSection, { global: { stubs: { NcSettingsSelectGroup: true, NcAvatar: true, DigestSection: { template: '<section data-test="digest" />' }, WebhookEventsSection: { template: '<section data-test="webhooks" />' } } } })
	await flushPromises()
	return wrapper
}

describe('the notifications section', () => {
	afterEach(() => {
		vi.mocked(fetchNotifications).mockReset()
	})

	test('who is notified, the email severity, the digest, the table per check and the webhook events', async () => {
		const wrapper = await mountTab()
		expect(wrapper.text()).toContain('Who is notified')
		expect(wrapper.text()).toContain('Also send an email for')
		expect(wrapper.text()).toContain('Send a test alert to me')
		expect(wrapper.find('[data-test="digest"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="per-check"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="webhooks"]').exists()).toBe(true)
	})

	test('the table per check starts collapsed', async () => {
		const wrapper = await mountTab()
		expect(wrapper.find('[data-test="per-check"] table').exists()).toBe(false)
		await wrapper.get('[data-test="per-check-toggle"] button').trigger('click')
		expect(wrapper.find('[data-test="per-check"] table').exists()).toBe(true)
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
		await wrapper.get('[data-test="per-check-toggle"] button').trigger('click')
		const row = wrapper.get('tbody tr').text()
		expect(row).toContain('Notified')
		expect(row).toContain('Not notified')
		expect(row).not.toContain('Told')
	})

	test('sending a test alert says so in a toast, and warns when no email went out', async () => {
		const wrapper = await mountTab()
		const send = () => wrapper.findAll('button').find((b) => b.text() === 'Send a test alert to me')!.trigger('click')

		vi.mocked(sendTestAlert).mockResolvedValue({ bell: true, email: 'sent', address: 'admin@example.com' })
		await send()
		await flushPromises()
		expect(showSuccess).toHaveBeenLastCalledWith('Test alert sent. Look at the bell at the top right. Email sent to admin@example.com. It can take a minute to arrive.')

		vi.mocked(sendTestAlert).mockResolvedValue({ bell: true, email: 'no_mail', address: null })
		await send()
		await flushPromises()
		expect(showSuccess).toHaveBeenLastCalledWith('Test alert sent. Look at the bell at the top right.')
		expect(showWarning).toHaveBeenCalledWith('No email: this server cannot send emails yet. Set up email in the basic settings.')
	})
})
