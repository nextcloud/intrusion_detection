/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ConfirmationOverview, GlobalSetting } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import ConfirmationSection from './ConfirmationSection.vue'
import { approveRequest, fetchConfirmation, fetchSettings, fetchUnconfirmableAccounts, rejectRequest, setConfirmationPreset, updateSettings } from '../../services/api.ts'
import { state } from '../../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchConfirmation: vi.fn(),
	fetchUnconfirmableAccounts: vi.fn(),
	approveRequest: vi.fn(),
	rejectRequest: vi.fn(),
	updateSettings: vi.fn(),
	setConfirmationPreset: vi.fn(),
	fetchSettings: vi.fn(() => new Promise(() => {})),
	fetchChecks: vi.fn(() => new Promise(() => {})),
}))

const mounted: { unmount: () => void }[] = []

/**
 * @param name - The setting
 * @param type - Its type
 * @param value - Its value
 */
function setting(name: string, type: GlobalSetting['type'], value: GlobalSetting['value']): GlobalSetting {
	return { name, type, default: value, min: type === 'duration' ? 60 : null, max: type === 'duration' ? 86400 * 180 : null, choices: type === 'choice' ? ['refuse', 'allow_notify', 'allow_force_change'] : [], value, label: `Label of ${name}`, help: '', unit: '', group: 'step_up' }
}

/**
 * @param overrides - Fields to change
 */
function overview(overrides: Partial<ConfirmationOverview> = {}): ConfirmationOverview {
	return {
		methods: [
			{ id: 'second_factor', name: 'Second factor', description: 'Accounts with two-factor authentication confirm with it.', state: 'on', note: null },
			{ id: 'known_device', name: 'Remembered device', description: 'A browser the user remembered.', state: 'on', note: null },
			{ id: 'email_code', name: 'Code by email', description: 'A 6-digit code.', state: 'unavailable', note: 'Nextcloud cannot send emails.' },
			{ id: 'admin_approval', name: 'Administrator approval', description: 'An administrator approves.', state: 'off', note: null },
		],
		preset: 'recommended',
		policies: [
			{ id: 'flagged_source', label: 'Login from an attacking address', why: 'The address was part of an attack.', default: 'refuse', outcome: 'refuse', setting: 'step_up_no_method_flagged_source', knownDevice: true, knownDeviceAllowed: true },
		],
		outcomes: [
			{ id: 'refuse', label: 'Refuse the login', description: 'Refused.' },
			{ id: 'allow_notify', label: 'Allow it and tell the user and you', description: 'Allowed.' },
			{ id: 'allow_force_change', label: 'Allow it and require a new password', description: 'New password.' },
		],
		users: { withoutMethod: 37, active: 200 },
		admins: { total: 3, withoutEmail: 1, withoutSecondFactor: 2, withNeither: ['bob'] },
		approvers: 3,
		approvals: [
			{ id: 7, uid: 'alice', displayName: 'Alice Liddell', ip: '203.0.113.7', createdAt: 1_760_000_000, expiresAt: 1_760_001_800, canDecide: true },
			{ id: 8, uid: 'admin', displayName: 'The Admin', ip: '203.0.113.8', createdAt: 1_760_000_000, expiresAt: 1_760_001_800, canDecide: false },
		],
		...overrides,
	}
}

/**
 * @param value - What the API returns
 */
async function mountTab(value = overview()) {
	vi.mocked(fetchConfirmation).mockResolvedValue(value)
	const wrapper = mount(ConfirmationSection, { attachTo: document.body })
	mounted.push(wrapper)
	await flushPromises()
	return wrapper
}

describe('the login confirmation section', () => {
	beforeEach(() => {
		state.settings = [
			setting('step_up_code_ttl', 'duration', 600),
			setting('step_up_no_method_flagged_source', 'choice', 'refuse'),
			setting('step_up_known_device_ok_for', 'string_list', ['flagged_source']),
			setting('step_up_admin_approval', 'bool', true),
			setting('step_up_admin_approval_ttl', 'duration', 1800),
			setting('known_device_enabled', 'bool', true),
			setting('known_device_duration', 'duration', 86400 * 180),
		]
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(fetchConfirmation).mockReset()
		vi.mocked(fetchUnconfirmableAccounts).mockReset()
		vi.mocked(approveRequest).mockReset()
		vi.mocked(rejectRequest).mockReset()
		vi.mocked(setConfirmationPreset).mockReset()
		vi.mocked(updateSettings).mockReset()
		document.body.innerHTML = ''
	})

	test('it starts with one decision, two switches and the accounts that cannot confirm; the fine control is collapsed', async () => {
		const wrapper = await mountTab()
		const options = wrapper.get('[data-test="preset"]').findAll('input[type="radio"]')
		expect(options.map((o) => o.attributes('value'))).toEqual(['recommended', 'refuse', 'allow'])
		expect((options[0]!.element as HTMLInputElement).checked).toBe(true)
		expect(wrapper.text()).toContain('Remember devices')
		expect(wrapper.text()).toContain('Administrators can approve logins')
		expect(wrapper.get('[data-test="users-count"]').text()).toContain('37 of 200 active accounts have no way to confirm a login')
		expect(wrapper.find('[data-test="policies"]').exists()).toBe(false)
		expect(wrapper.get('[data-test="reasons-toggle"] button').attributes('aria-expanded')).toBe('false')
		expect(wrapper.find('[data-test="methods"]').exists()).toBe(false)
		expect(wrapper.text()).not.toContain('Label of step_up_code_ttl')
		expect(wrapper.find('[data-test="users-without"]').exists()).toBe(true)
	})

	test('logins waiting for an administrator are in reach', async () => {
		const wrapper = await mountTab()
		expect(wrapper.find('#settings-approvals').exists()).toBe(true)
		expect(wrapper.get('[data-test="approvals"]').text()).toContain('Alice Liddell')
	})

	test('one choice sets the outcome of every reason', async () => {
		vi.mocked(setConfirmationPreset).mockResolvedValue({ preset: 'refuse', policies: overview().policies })
		const wrapper = await mountTab()
		await wrapper.get('input[value="refuse"]').setValue(true)
		await flushPromises()
		expect(setConfirmationPreset).toHaveBeenCalledWith('refuse')
		expect(fetchSettings).toHaveBeenCalled()
		expect((wrapper.get('input[value="refuse"]').element as HTMLInputElement).checked).toBe(true)
	})

	test('a mix set per reason is custom and leads to the reasons table', async () => {
		Element.prototype.scrollIntoView = vi.fn()
		const wrapper = await mountTab(overview({ preset: 'custom' }))
		expect(wrapper.get('[data-test="preset"]').findAll('input').some((o) => (o.element as HTMLInputElement).checked)).toBe(false)
		const note = wrapper.get('[data-test="preset-custom"]')
		expect(note.text()).toContain('Custom')
		await note.get('button').trigger('click')
		await nextTick()
		expect(wrapper.find('[data-test="policies"]').exists()).toBe(true)
		expect(Element.prototype.scrollIntoView).toHaveBeenCalled()
	})

	test('the switches save at once', async () => {
		vi.mocked(updateSettings).mockResolvedValue({ settings: [setting('known_device_enabled', 'bool', false)], templates: {} })
		const wrapper = await mountTab()
		const toggle = wrapper.findAll('input[type="checkbox"]')[0]!
		await toggle.setValue(false)
		await flushPromises()
		expect(updateSettings).toHaveBeenCalledWith({ known_device_enabled: false })
	})

	test('shows the methods in the order they are tried, with their state', async () => {
		const wrapper = await mountTab()
		await wrapper.get('[data-test="confirmation-more"] button').trigger('click')
		const steps = wrapper.get('[data-test="methods"]').findAll('li')
		expect(steps.map((s) => s.attributes('data-method'))).toEqual(['second_factor', 'known_device', 'email_code', 'admin_approval'])
		expect(steps[2]!.text()).toContain('Not available')
		expect(steps[2]!.text()).toContain('Nextcloud cannot send emails.')
		expect(steps[3]!.text()).toContain('Off')
	})

	test('it edits the reasons in their table and every other confirmation setting in its own card', async () => {
		const wrapper = await mountTab()
		await wrapper.get('[data-test="reasons-toggle"] button').trigger('click')
		await wrapper.get('[data-test="confirmation-more"] button').trigger('click')
		expect(wrapper.get('[data-test="policies"]').text()).toContain('Login from an attacking address')
		const text = wrapper.text()
		expect(text).toContain('Label of step_up_code_ttl')
		expect(text).toContain('Label of known_device_duration')
		expect(text).toContain('Label of step_up_admin_approval_ttl')
		expect(text).not.toContain('Label of step_up_no_method_flagged_source')
		expect(text).not.toContain('Label of step_up_known_device_ok_for')
	})

	test('counts the accounts that cannot confirm, administrators highlighted', async () => {
		const wrapper = await mountTab()
		expect(wrapper.get('[data-test="users-without"]').text()).toContain('37')
		expect(wrapper.get('[data-test="users-without"]').text()).toContain('of 200 active accounts cannot confirm a login')
		expect(wrapper.get('[data-test="admins-without"]').text()).toContain('1')
	})

	test('lists the accounts on request', async () => {
		vi.mocked(fetchUnconfirmableAccounts).mockResolvedValue([{ uid: 'carol', displayName: 'Carol', lastLogin: 1_760_000_000, groups: ['staff'], admin: false }])
		const wrapper = await mountTab()
		await wrapper.findAll('button').find((b) => b.text() === 'Show accounts')!.trigger('click')
		await flushPromises()
		expect(fetchUnconfirmableAccounts).toHaveBeenCalledWith(50, 0, false)
		expect(wrapper.get('[data-test="accounts"]').text()).toContain('Carol')
		expect(wrapper.get('[data-test="accounts"]').text()).toContain('staff')
	})

	test('approving a waiting login asks first, then the list is loaded again', async () => {
		vi.mocked(approveRequest).mockResolvedValue({})
		const wrapper = await mountTab()
		const rows = wrapper.get('[data-test="approvals"]').findAll('li')
		expect(rows[1]!.text()).toContain('Your own login: another administrator decides')
		expect(rows[1]!.findAll('button')).toHaveLength(0)

		await rows[0]!.findAll('button').find((b) => b.text() === 'Approve')!.trigger('click')
		await flushPromises()
		expect(approveRequest).not.toHaveBeenCalled()
		const confirm = [...document.body.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Approve login')
		expect(confirm).toBeDefined()
		expect(document.body.textContent).toContain('Approve only if you know it is really them')
		confirm!.click()
		await flushPromises()
		expect(approveRequest).toHaveBeenCalledWith(7)
		expect(fetchConfirmation).toHaveBeenCalledTimes(2)
	})

	test('rejecting needs no extra question', async () => {
		vi.mocked(rejectRequest).mockResolvedValue({})
		const wrapper = await mountTab()
		await wrapper.get('[data-test="approvals"]').findAll('button').find((b) => b.text() === 'Reject')!.trigger('click')
		await flushPromises()
		expect(rejectRequest).toHaveBeenCalledWith(7)
	})

	test('says so when no login is waiting', async () => {
		const wrapper = await mountTab(overview({ approvals: [] }))
		expect(wrapper.text()).toContain('No login is waiting')
	})
})
