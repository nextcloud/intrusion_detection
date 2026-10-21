/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Lockdown, LockdownStatus, Status } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import StatusBanner from '../StatusBanner.vue'
import { endLockdown, extendLockdown, fetchLockdown, startLockdown } from '../../services/api.ts'
import { effectsSentence, formatUntil } from './summary.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchLockdown: vi.fn(),
	startLockdown: vi.fn(),
	extendLockdown: vi.fn(),
	endLockdown: vi.fn(),
	fetchStatus: vi.fn(() => new Promise(() => {})),
}))

const NOW = 1_760_000_000

/**
 * @param lockdown - The running lockdown, if any
 */
function status(lockdown?: LockdownStatus): Status {
	return {
		state: 'protecting',
		learning: { active: false, until: 0, daysLeft: 0, minDays: 1, maxDays: 30 },
		checks: { protect: 12, observe: 1, off: 2 },
		last24h: { detections: 0, enforced: 0, observed: 0, blockedAddresses: 0, wouldHaveBlocked: 0, accounts: 0, categories: [] },
		activeBans: 0,
		prerequisites: { memoryCache: 'distributed', mail: true },
		cost: null,
		costSampleRate: 1000,
		problems: [],
		extensions: lockdown ? { lockdown: lockdown as unknown as Record<string, unknown> } : {},
	}
}

const running: LockdownStatus = { active: true, until: NOW + 6 * 3600, startedAt: NOW, startedBy: 'alice', reason: 'credential stuffing from botnet', automatic: false, effects: ['login', 'devices', 'reset'] }

/**
 * @param overrides - Fields to change
 */
function lockdown(overrides: Partial<Lockdown> = {}): Lockdown {
	return {
		active: false,
		until: 0,
		startedAt: 0,
		startedBy: '',
		reason: '',
		automatic: false,
		effects: [
			{ id: 'login', label: 'Confirm every password login', description: 'Every login with a password needs a second factor.', enabled: true },
			{ id: 'devices', label: 'No new app passwords or device connections', description: 'Creating app passwords is refused.', enabled: true },
			{ id: 'limits', label: 'Lower the limits of the checks', description: 'Multiplied by {lockdown_factor}.', enabled: false },
		],
		defaultDuration: 6 * 3600,
		minDuration: 3600,
		maxDuration: 86400,
		maxReason: 200,
		usersWithoutMethod: 37,
		history: [],
		...overrides,
	}
}

const buttons = (text: string) => [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === text)

describe('lockdown on the status banner', () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ['Date'] })
		vi.setSystemTime(NOW * 1000)
		vi.mocked(fetchLockdown).mockResolvedValue(lockdown())
	})

	afterEach(() => {
		vi.useRealTimers()
		vi.mocked(startLockdown).mockReset()
		vi.mocked(extendLockdown).mockReset()
		vi.mocked(endLockdown).mockReset()
		document.body.innerHTML = ''
	})

	test('a running lockdown takes over the banner: until when, who, why and what it does', () => {
		const wrapper = mount(StatusBanner, { props: { status: status(running) } })
		expect(wrapper.get('section').attributes('data-state')).toBe('lockdown')
		expect(wrapper.get('h3').text()).toBe(`Lockdown until ${formatUntil(running.until)}.`)
		const text = wrapper.text()
		expect(text).toContain('Started by alice: "credential stuffing from botnet".')
		expect(text).toContain('Every password login needs confirmation, new devices cannot be connected, password reset is paused.')
		expect(wrapper.findAll('button').map((b) => b.text())).toEqual(['Extend', 'End lockdown'])
	})

	test('without a lockdown, the banner offers to start one', () => {
		const wrapper = mount(StatusBanner, { props: { status: status() } })
		expect(wrapper.get('section').attributes('data-state')).toBe('protecting')
		expect(wrapper.findAll('button').map((b) => b.text())).toContain('Start lockdown')
		expect(mount(StatusBanner, { props: { status: { ...status(), state: 'off' } } }).text()).not.toContain('Start lockdown')
	})

	test('the start dialog lists every effect with its switch, says who cannot log in, and starts it', async () => {
		vi.mocked(startLockdown).mockResolvedValue(lockdown({ active: true }))
		const wrapper = mount(StatusBanner, { props: { status: status() }, attachTo: document.body })
		await wrapper.findAll('button').find((b) => b.text() === 'Start lockdown')!.trigger('click')
		await flushPromises()
		const dialog = document.body.querySelector('[role="dialog"]')!
		expect(dialog.querySelectorAll('[data-effect]')).toHaveLength(3)
		expect(dialog.textContent).toContain('currently 37 users. App passwords keep working.')
		const reason = dialog.querySelector('textarea')!
		reason.value = 'botnet'
		reason.dispatchEvent(new Event('input'))
		const limits = dialog.querySelector<HTMLInputElement>('input[data-effect="limits"]')!
		limits.click()
		await flushPromises()
		buttons('Start lockdown').at(-1)!.click()
		await flushPromises()
		expect(startLockdown).toHaveBeenCalledWith(6 * 3600, 'botnet', ['login', 'devices', 'limits'])
		wrapper.unmount()
	})

	test('without the login effect, nobody is locked out, and the dialog does not say so', async () => {
		vi.mocked(fetchLockdown).mockResolvedValue(lockdown({ effects: [{ id: 'devices', label: 'No new devices', description: '', enabled: true }] }))
		const wrapper = mount(StatusBanner, { props: { status: status() }, attachTo: document.body })
		await wrapper.findAll('button').find((b) => b.text() === 'Start lockdown')!.trigger('click')
		await flushPromises()
		expect(document.body.querySelector('[data-test="impact"]')).toBeNull()
		wrapper.unmount()
	})

	test('ending asks first and names the consequence', async () => {
		vi.mocked(endLockdown).mockResolvedValue(lockdown())
		const wrapper = mount(StatusBanner, { props: { status: status(running) }, attachTo: document.body })
		await wrapper.findAll('button').find((b) => b.text() === 'End lockdown')!.trigger('click')
		await flushPromises()
		expect(endLockdown).not.toHaveBeenCalled()
		expect(document.body.textContent).toContain('work as usual again at once')
		buttons('End lockdown').at(-1)!.click()
		await flushPromises()
		expect(endLockdown).toHaveBeenCalledOnce()
		wrapper.unmount()
	})

	test('extending offers no more than 24 hours from now', async () => {
		vi.mocked(extendLockdown).mockResolvedValue(lockdown({ active: true }))
		const wrapper = mount(StatusBanner, { props: { status: status(running) }, attachTo: document.body })
		await wrapper.findAll('button').find((b) => b.text() === 'Extend')!.trigger('click')
		await flushPromises()
		buttons('Extend lockdown').at(-1)!.click()
		await flushPromises()
		expect(extendLockdown).toHaveBeenCalledWith(2 * 3600)
		wrapper.unmount()
	})

	test('the effects read as one sentence', () => {
		expect(effectsSentence(['reset'])).toBe('Password reset is paused.')
		expect(effectsSentence([])).toBe('All of its effects are switched off.')
	})
})
