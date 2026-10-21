/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { AccountGuide } from '../../secureAccountTypes.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import SecureAccountPanel from './SecureAccountPanel.vue'
import { confirmPasswordReset, fetchAccountGuide, reenableAccount } from '../../services/secureAccount.ts'
import { makeDetail } from '../../tests/fixtures.ts'

vi.mock('../../services/secureAccount.ts', () => ({
	fetchAccountGuide: vi.fn(),
	reenableAccount: vi.fn(),
	confirmPasswordReset: vi.fn(),
}))

const AT = Date.UTC(2026, 9, 20, 10, 2) / 1000
const mounted: { unmount: () => void }[] = []

afterEach(() => {
	mounted.splice(0).forEach((w) => w.unmount())
	vi.clearAllMocks()
	document.body.innerHTML = ''
})

/**
 * @param overrides - Fields to change
 */
function guide(overrides: Partial<AccountGuide> = {}): AccountGuide {
	return {
		uid: 'alice',
		displayName: 'Alice',
		exists: true,
		enabled: true,
		lockedByLink: false,
		canReenable: false,
		progress: {
			active: true,
			startedAt: AT,
			eventAt: AT,
			reason: 'denied',
			detectionId: 42,
			closedAt: null,
			closedBy: null,
			done: 4,
			total: 6,
			steps: ['password', 'sessions', 'two_factor', 'email', 'shares', 'files'].map((id, i) => ({ id: id as never, done: i < 4, doneAt: i < 4 ? AT : null, skipped: false, managed: false, userConfirms: i > 0 })),
		},
		...overrides,
	}
}

/**
 * @param data - What the server returns
 */
async function render(data: AccountGuide) {
	vi.mocked(fetchAccountGuide).mockResolvedValue(data)
	const wrapper = mount(SecureAccountPanel, { props: { detail: makeDetail() }, attachTo: document.body })
	mounted.push(wrapper)
	await flushPromises()
	return wrapper
}

describe('SecureAccountPanel', () => {
	test('shows how far the user got', async () => {
		const wrapper = await render(guide())
		expect(wrapper.text()).toContain('Secure my account: 4 of 6 steps done')
		expect(wrapper.findAll('li')).toHaveLength(6)
	})

	test('shows nothing for an account without a checklist', async () => {
		const wrapper = await render(guide({ progress: null }))
		expect(wrapper.find('section').exists()).toBe(false)
	})

	test('a locked account can be enabled again after a confirmation', async () => {
		vi.mocked(reenableAccount).mockResolvedValue(guide({ lockedByLink: true, enabled: true }))
		const wrapper = await render(guide({ lockedByLink: true, enabled: false, canReenable: true, progress: null }))
		expect(wrapper.text()).toContain('The account is locked')
		await wrapper.findAll('button').find((b) => b.text() === 'Re-enable and start Secure my account')!.trigger('click')
		await flushPromises()
		expect(reenableAccount).not.toHaveBeenCalled()
		const confirm = [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Enable the account' && b.closest('[role="dialog"]'))
		expect(confirm).toBeDefined()
		confirm!.click()
		await flushPromises()
		expect(reenableAccount).toHaveBeenCalledWith(makeDetail().detection.id)
		expect(wrapper.text()).toContain('The account is enabled again.')
	})

	test('a password managed elsewhere is marked done by the administrator', async () => {
		const data = guide()
		data.progress!.steps[0] = { ...data.progress!.steps[0]!, done: false, managed: true }
		vi.mocked(confirmPasswordReset).mockResolvedValue(guide())
		const wrapper = await render(data)
		await wrapper.findAll('button').find((b) => b.text() === 'Password was reset in the directory')!.trigger('click')
		await flushPromises()
		expect(confirmPasswordReset).toHaveBeenCalled()
	})
})
