/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { showError, showSuccess } from '@nextcloud/dialogs'
import { PasswordConfirmationCancelledError } from '@nextcloud/password-confirmation'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { ApiError } from '../services/api.ts'
import { useAction } from './useAction.ts'
import { useAnnouncer } from './useAnnouncer.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

/**
 * What the page's live region says once the announcer's delay passed.
 */
function announced(): string {
	vi.advanceTimersByTime(100)
	return useAnnouncer().message.value
}

describe('useAction', () => {
	beforeEach(() => {
		vi.useFakeTimers()
		useAnnouncer().message.value = ''
		vi.mocked(showError).mockClear()
		vi.mocked(showSuccess).mockClear()
	})
	afterEach(() => {
		vi.useRealTimers()
	})

	test('is busy with its key while it runs', async () => {
		const { busy, run } = useAction()
		let finish!: () => void
		const running = run('save', () => new Promise<void>((resolve) => {
			finish = resolve
		}), { fallback: 'Failed' })
		expect(busy.value).toBe('save')
		finish()
		expect(await running).toBe(true)
		expect(busy.value).toBeNull()
	})

	test('announces what worked, or shows it in a toast, never both', async () => {
		const { run } = useAction()
		await run('a', async () => 42, { done: (value) => `Got ${value}`, fallback: 'Failed' })
		expect(announced()).toBe('Got 42')
		expect(showSuccess).not.toHaveBeenCalled()

		useAnnouncer().message.value = ''
		await run('b', async () => undefined, { done: 'Saved', toast: true, fallback: 'Failed' })
		expect(showSuccess).toHaveBeenCalledWith('Saved')
		expect(announced()).toBe('')
	})

	test('shows the server\'s message or the fallback in a toast', async () => {
		const { run } = useAction()
		expect(await run('a', () => Promise.reject(new ApiError('Not allowed')), { fallback: 'Failed' })).toBe(false)
		expect(showError).toHaveBeenLastCalledWith('Not allowed')
		await run('a', () => Promise.reject(new Error('offline')), { fallback: 'Failed' })
		expect(showError).toHaveBeenLastCalledWith('Failed')
		expect(announced()).toBe('')
	})

	test('keeps an inline failure for an error note instead of a toast', async () => {
		const { error, run } = useAction()
		await run('a', () => Promise.reject(new Error('offline')), { fallback: 'Failed', inline: true })
		expect(error.value).toBe('Failed')
		expect(showError).not.toHaveBeenCalled()
		await run('a', async () => undefined, { fallback: 'Failed', inline: true })
		expect(error.value).toBeNull()
	})

	test('announces a failure the component shows itself', async () => {
		const { run } = useAction()
		const handle = vi.fn(() => true)
		await run('a', () => Promise.reject(new ApiError('Too long', 'name')), { fallback: 'Failed', handle })
		expect(handle).toHaveBeenCalled()
		expect(showError).not.toHaveBeenCalled()
		expect(announced()).toBe('Too long')
	})

	test('a closed password dialog is no failure', async () => {
		const { error, run } = useAction()
		expect(await run('a', () => Promise.reject(new PasswordConfirmationCancelledError()), { fallback: 'Failed', inline: true })).toBe(false)
		expect(error.value).toBeNull()
		expect(showError).not.toHaveBeenCalled()
	})
})
