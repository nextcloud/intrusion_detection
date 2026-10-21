/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { DigestOverview } from '../../types.ts'

import { showError, showSuccess } from '@nextcloud/dialogs'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import DigestSection from './DigestSection.vue'
import { ApiError, fetchDigest, sendTestDigest, updateSettings } from '../../services/api.ts'
import { state } from '../../store.ts'

const mounted: { unmount: () => void }[] = []

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDigest: vi.fn(),
	sendTestDigest: vi.fn(),
	updateSettings: vi.fn(),
	fetchChecks: vi.fn(() => new Promise(() => {})),
}))

/**
 * @param overrides - Fields to change
 */
function overview(overrides: Partial<DigestOverview> = {}): DigestOverview {
	return {
		frequency: 'weekly',
		sendQuiet: true,
		timezone: 'Europe/Berlin',
		nextDue: Date.UTC(2026, 9, 26, 7, 0) / 1000,
		last: { period: Date.UTC(2026, 9, 19, 6, 0) / 1000, sentAt: Date.UTC(2026, 9, 19, 6, 5) / 1000, result: 'sent', recipients: 2, failed: 0 },
		recipients: 2,
		withoutEmail: [],
		withoutEmailCount: 0,
		mailConfigured: true,
		viewerHasEmail: true,
		...overrides,
	}
}

/**
 * Mount the section once the overview is loaded.
 *
 * @param value - What the API returns
 */
async function mountSection(value = overview()) {
	vi.mocked(fetchDigest).mockResolvedValue(value)
	const wrapper = mount(DigestSection, { attachTo: document.body })
	mounted.push(wrapper)
	await flushPromises()
	return wrapper
}

describe('DigestSection', () => {
	beforeEach(() => {
		state.settings = [
			{ name: 'digest_frequency', type: 'choice', default: 'weekly', min: null, max: null, choices: ['off', 'daily', 'weekly'], value: 'weekly', label: 'Send the digest', help: '', unit: '', group: 'notifications' },
			{ name: 'digest_send_quiet', type: 'bool', default: true, min: null, max: null, choices: [], value: true, label: 'Also send quiet digests', help: '', unit: '', group: 'notifications' },
			{ name: 'notify_admin_group', type: 'string_list', default: ['admin'], min: null, max: null, choices: [], value: ['admin'], label: 'Notify these groups', help: '', unit: '', group: 'notifications' },
		]
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(fetchDigest).mockReset()
		vi.mocked(sendTestDigest).mockReset()
		vi.mocked(updateSettings).mockReset()
		vi.mocked(showSuccess).mockReset()
		vi.mocked(showError).mockReset()
		document.body.innerHTML = ''
	})

	test('shows its own settings, the next digest and who gets it', async () => {
		const wrapper = await mountSection()
		expect(wrapper.text()).toContain('Digest email')
		expect(wrapper.text()).toContain('Also send quiet digests')
		expect(wrapper.text()).not.toContain('Notify these groups')
		expect(wrapper.get('[data-test="digest-schedule"]').text()).toContain('(Europe/Berlin)')
		expect(wrapper.get('[data-test="digest-schedule"]').text()).toContain('Next digest:')
		expect(wrapper.get('[data-test="digest-last"]').text()).toContain('Sent to 2 people')
		expect(wrapper.get('[data-test="digest-recipients"]').text()).toBe('The digest goes to 2 people in the notification groups.')
	})

	test('says who is skipped for lack of an email address', async () => {
		const wrapper = await mountSection(overview({
			recipients: 1,
			withoutEmail: [{ uid: 'bob', displayName: 'Bob Builder' }, { uid: 'carol', displayName: '' }],
			withoutEmailCount: 3,
		}))
		expect(wrapper.get('[data-test="digest-recipients"]').text()).toBe('The digest goes to 1 person in the notification groups. Bob Builder, carol and 1 more have no email address and get none.')
	})

	test('an off digest says so, and a quiet period that was skipped is explained', async () => {
		const wrapper = await mountSection(overview({ frequency: 'off', nextDue: null, last: { period: 1, sentAt: 1, result: 'quiet_skipped', recipients: 0, failed: 0 } }))
		expect(wrapper.get('[data-test="digest-schedule"]').text()).toContain('The digest is off.')
		expect(wrapper.get('[data-test="digest-last"]').text()).toContain('quiet digests are off')
	})

	test('leaves the missing email server to the one warning of the tab', async () => {
		const wrapper = await mountSection(overview({ mailConfigured: false }))
		expect(wrapper.text()).not.toContain('email server')
		expect(wrapper.find('[data-test="digest-schedule"]').exists()).toBe(true)
	})

	test('sends a test digest to the admin only and reports the result', async () => {
		vi.mocked(sendTestDigest).mockResolvedValue({ message: 'The test digest was sent to admin@example.com.' })
		const wrapper = await mountSection()
		const button = wrapper.findAll('button').find((b) => b.text() === 'Send a test digest now')!
		expect(button.attributes('disabled')).toBeUndefined()
		expect(wrapper.text()).toContain('Only you get it, marked as a test.')
		await button.trigger('click')
		await flushPromises()
		expect(sendTestDigest).toHaveBeenCalledOnce()
		expect(showSuccess).toHaveBeenCalledWith('The test digest was sent to admin@example.com.')
	})

	test('a refused test digest shows the reason', async () => {
		vi.mocked(sendTestDigest).mockRejectedValue(new ApiError('The test digest could not be sent.'))
		const wrapper = await mountSection()
		await wrapper.findAll('button').find((b) => b.text() === 'Send a test digest now')!.trigger('click')
		await flushPromises()
		expect(showError).toHaveBeenCalledWith('The test digest could not be sent.')
	})

	test('without an email address the test button is disabled and says why', async () => {
		const wrapper = await mountSection(overview({ viewerHasEmail: false }))
		const button = wrapper.findAll('button').find((b) => b.text() === 'Send a test digest now')!
		expect(button.attributes('disabled')).toBeDefined()
		expect(wrapper.text()).toContain('Add an email address to your account')
	})

	test('the schedule is loaded again when the frequency was saved', async () => {
		await mountSection()
		expect(fetchDigest).toHaveBeenCalledTimes(1)
		state.settings = state.settings.map((s) => (s.name === 'digest_frequency' ? { ...s, value: 'daily' } : s))
		await flushPromises()
		expect(fetchDigest).toHaveBeenCalledTimes(2)
	})
})
