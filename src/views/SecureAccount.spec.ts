/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { SecureAccount, SecureAccountStepId } from '../secureAccountTypes.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import SecureAccountView from './SecureAccount.vue'
import { changePassword, completeStep, deleteShare, fetchSecureAccount, revokeSession, startSecureAccount } from '../services/secureAccount.ts'

vi.mock('../services/secureAccount.ts', () => ({
	fetchSecureAccount: vi.fn(),
	startSecureAccount: vi.fn(),
	completeStep: vi.fn(),
	dismissSecureAccount: vi.fn(),
	revokeSession: vi.fn(),
	deleteShare: vi.fn(),
	changePassword: vi.fn(),
}))

const AT = Date.UTC(2026, 9, 20, 10, 2) / 1000
const mounted: { unmount: () => void }[] = []

afterEach(() => {
	mounted.splice(0).forEach((w) => w.unmount())
	vi.clearAllMocks()
})

/**
 * @param done - The steps that are done
 * @param overrides - Fields to change
 */
function account(done: SecureAccountStepId[] = [], overrides: Partial<SecureAccount> = {}): SecureAccount {
	const ids: SecureAccountStepId[] = ['password', 'sessions', 'two_factor', 'email', 'shares', 'files']
	return {
		progress: {
			active: true,
			startedAt: AT,
			eventAt: AT - 600,
			reason: 'denied',
			detectionId: '42',
			closedAt: null,
			closedBy: null,
			done: done.length,
			total: 6,
			steps: ids.map((id) => ({
				id,
				done: done.includes(id),
				doneAt: done.includes(id) ? AT : null,
				skipped: false,
				managed: false,
				userConfirms: ['sessions', 'email', 'shares', 'files'].includes(id),
			})),
		},
		since: AT - 7 * 86400,
		sessions: [
			{ id: 11, name: 'Firefox on Linux', kind: 'session', current: true, lastActivity: AT, createdAt: null, address: null, afterEvent: false },
			{ id: 12, name: 'Sync client', kind: 'app_password', current: false, lastActivity: AT, createdAt: AT, address: '203.0.113.7', afterEvent: true },
		],
		changes: [
			{ id: '1', type: 'email_changed', label: 'Email address changed', via: 'self', actor: null, previous: 'a***@example.com', new: 'e***@evil.example', detail: null, address: '203.0.113.7', createdAt: AT },
		],
		shares: [
			{ id: 'ocinternal:5', name: 'Finance', type: 'link', recipient: null, createdAt: AT, hasPassword: false, expiresAt: null, isFolder: true },
		],
		email: 'alice@example.com',
		canChangePassword: true,
		links: { security: '/settings/user/security', personalInfo: '/settings/user', activity: '/apps/activity', trash: '/apps/files/trashbin' },
		...overrides,
	}
}

/**
 * @param data - What the server returns
 */
async function render(data: SecureAccount) {
	vi.mocked(fetchSecureAccount).mockResolvedValue(data)
	const wrapper = mount(SecureAccountView)
	mounted.push(wrapper)
	await flushPromises()
	return wrapper
}

/**
 * @param wrapper - The mounted page
 * @param text - The button's text
 */
function button(wrapper: Awaited<ReturnType<typeof render>>, text: string) {
	return wrapper.findAll('button').find((b) => b.text().includes(text))
}

describe('SecureAccount', () => {
	test('shows the progress and every step', async () => {
		const wrapper = await render(account(['password', 'two_factor']))
		expect(wrapper.text()).toContain('2 of 6 steps done')
		expect(wrapper.text()).toContain('You said that something on your account was not you')
		expect(wrapper.findAll('ol > li')).toHaveLength(6)
		expect(wrapper.text()).toContain('Check your devices and sessions')
	})

	test('numbers only the steps that apply and shows one segment per step', async () => {
		const data = account(['password'])
		data.progress.steps[2]!.skipped = true
		data.progress.total = 5
		const wrapper = await render(data)
		const markers = wrapper.findAll('ol > li').map((li) => li.get('button span').text())
		expect(markers).toEqual(['', '2', '', '3', '4', '5'])
		const bar = wrapper.get('[data-test="checklist-progress"]')
		expect(bar.attributes('aria-valuenow')).toBe('1')
		expect(bar.attributes('aria-valuemax')).toBe('5')
		expect(bar.findAll('span')).toHaveLength(5)
	})

	test('keeps one step open at a time, the next one to do', async () => {
		vi.mocked(completeStep).mockResolvedValue(account(['password', 'sessions']))
		const wrapper = await render(account(['password']))
		const open = () => wrapper.findAll('ol > li > h3 > button').filter((b) => b.attributes('aria-expanded') === 'true').map((b) => b.text())
		expect(open()).toHaveLength(1)
		expect(open()[0]).toContain('Check your devices and sessions')
		await wrapper.findAll('ol > li > h3 > button')[3]!.trigger('click')
		expect(open()).toHaveLength(1)
		expect(open()[0]).toContain('Check your email address and profile')
		await wrapper.findAll('ol > li > h3 > button')[3]!.trigger('click')
		expect(open()).toHaveLength(0)
	})

	test('marks entries created after the event and revokes them', async () => {
		vi.mocked(revokeSession).mockResolvedValue(undefined)
		const wrapper = await render(account())
		expect(wrapper.text()).toContain('New since the event')
		expect(wrapper.text()).toContain('This device')
		const revoke = wrapper.findAll('button').filter((b) => b.text() === 'Revoke')
		// The current session cannot be revoked from here.
		expect(revoke).toHaveLength(1)
		await revoke[0]!.trigger('click')
		await flushPromises()
		expect(revokeSession).toHaveBeenCalledWith(12)
		expect(fetchSecureAccount).toHaveBeenCalledTimes(2)
	})

	test('the user confirms the steps they check themselves', async () => {
		vi.mocked(completeStep).mockResolvedValue(account(['sessions']))
		const wrapper = await render(account())
		const confirm = wrapper.findAll('button').filter((b) => b.text() === 'I have checked this')
		// Devices, shares and files; email has its own wording.
		expect(confirm).toHaveLength(3)
		expect(button(wrapper, 'My email address and profile are correct')).toBeDefined()
		await confirm[0]!.trigger('click')
		await flushPromises()
		expect(completeStep).toHaveBeenCalledWith('sessions')
		expect(wrapper.text()).toContain('1 of 6 steps done')
	})

	test('changes the password inline', async () => {
		vi.mocked(changePassword).mockResolvedValue(undefined)
		const wrapper = await render(account())
		const inputs = wrapper.findAll('input[type="password"]')
		await inputs[0]!.setValue('old secret')
		await inputs[1]!.setValue('A-new-long-passphrase')
		await wrapper.find('form').trigger('submit')
		await flushPromises()
		expect(changePassword).toHaveBeenCalledWith('old secret', 'A-new-long-passphrase')
	})

	test('a password managed elsewhere is left to the administrator', async () => {
		const data = account()
		data.progress.steps[0]!.managed = true
		const wrapper = await render(data)
		expect(wrapper.text()).toContain('Your password is managed by your organisation')
		expect(wrapper.find('form').exists()).toBe(false)
	})

	test('deletes a recent share', async () => {
		vi.mocked(deleteShare).mockResolvedValue(undefined)
		const wrapper = await render(account())
		expect(wrapper.text()).toContain('Public link')
		expect(wrapper.text()).toContain('no password')
		await button(wrapper, 'Delete')!.trigger('click')
		await flushPromises()
		expect(deleteShare).toHaveBeenCalledWith('ocinternal:5')
	})

	test('a user without email address is asked to add one', async () => {
		const wrapper = await render(account([], { email: null }))
		expect(wrapper.text()).toContain('Add an email address so Nextcloud can reach you if this happens again.')
	})

	test('without an open checklist it can be started', async () => {
		const closed = account()
		closed.progress = { ...closed.progress, active: false, startedAt: null, reason: null }
		vi.mocked(startSecureAccount).mockResolvedValue(account())
		const wrapper = await render(closed)
		expect(wrapper.text()).toContain('Nothing to do right now')
		await button(wrapper, 'Start the checklist')!.trigger('click')
		await flushPromises()
		expect(startSecureAccount).toHaveBeenCalled()
		expect(wrapper.findAll('ol > li')).toHaveLength(6)
	})

	test('texts from the server are shown as text, never as markup', async () => {
		const data = account()
		data.sessions[1]!.name = '<img src=x onerror=alert(1)>'
		const wrapper = await render(data)
		expect(wrapper.find('img').exists()).toBe(false)
		expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>')
	})
})
