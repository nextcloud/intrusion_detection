/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { showError, showSuccess } from '@nextcloud/dialogs'
import { PasswordConfirmationCancelledError } from '@nextcloud/password-confirmation'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import LogOutElsewhere from './LogOutElsewhere.vue'
import { ApiError } from '../../services/api.ts'
import { logOutElsewhere } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	logOutElsewhere: vi.fn(),
}))

const mounted: { unmount: () => void }[] = []

/**
 * Open the dialog and press its button.
 */
async function runFromDialog() {
	const wrapper = mount(LogOutElsewhere, { attachTo: document.body })
	mounted.push(wrapper)
	await wrapper.get('[data-test="log-out-elsewhere-button"]').trigger('click')
	await flushPromises()
	expect(logOutElsewhere).not.toHaveBeenCalled()
	const button = [...document.body.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent?.trim() === 'Log out other browsers') as HTMLButtonElement
	button.click()
	await flushPromises()
	return wrapper
}

describe('LogOutElsewhere', () => {
	beforeEach(() => {
		personal.devicesVersion = 0
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(logOutElsewhere).mockReset()
		vi.mocked(showError).mockReset()
		vi.mocked(showSuccess).mockReset()
		document.body.innerHTML = ''
	})

	test('says how it differs from revoking all sessions: apps stay connected', () => {
		const wrapper = mount(LogOutElsewhere)
		expect(wrapper.text()).toContain('Unlike "Revoke all other sessions" above, your apps and app passwords stay connected.')
	})

	test('asks first, then logs out the other browsers and reloads the devices', async () => {
		vi.mocked(logOutElsewhere).mockResolvedValue({ sessions: 2, devices: 1 })
		await runFromDialog()
		expect(logOutElsewhere).toHaveBeenCalledTimes(1)
		expect(showSuccess).toHaveBeenCalledWith('Logged out of 2 other browsers. 1 remembered device was forgotten.')
		expect(personal.devicesVersion).toBe(1)
	})

	test('does nothing when the password dialog is closed', async () => {
		vi.mocked(logOutElsewhere).mockRejectedValue(new PasswordConfirmationCancelledError())
		await runFromDialog()
		expect(showError).not.toHaveBeenCalled()
		expect(showSuccess).not.toHaveBeenCalled()
	})

	test('shows the server\'s explanation when it cannot be done', async () => {
		vi.mocked(logOutElsewhere).mockRejectedValue(new ApiError('This can only be done from a browser session, not with an app password.'))
		await runFromDialog()
		expect(showError).toHaveBeenCalledWith('This can only be done from a browser session, not with an app password.')
		expect(personal.devicesVersion).toBe(0)
	})
})
