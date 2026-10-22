/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { SecurityEvent } from '../types.ts'

import { showError, showSuccess } from '@nextcloud/dialogs'
import { PasswordConfirmationCancelledError } from '@nextcloud/password-confirmation'
import { flushPromises, mount } from '@vue/test-utils'
import { AxiosError, AxiosHeaders } from 'axios'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import EventItem from './EventItem.vue'
import { ApiError } from '../../services/api.ts'
import { activity, overview, securityEvent } from '../../tests/personalFixtures.ts'
import { confirmEvent, denyEvent, fetchActivity, fetchOverview } from '../api.ts'
import { personal } from '../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	confirmEvent: vi.fn(),
	denyEvent: vi.fn(),
	fetchActivity: vi.fn(),
	fetchOverview: vi.fn(),
}))

const mounted: { unmount: () => void }[] = []

/**
 * @param event - The event
 */
function mountItem(event: SecurityEvent) {
	const wrapper = mount(EventItem, { props: { event }, attachTo: document.body })
	mounted.push(wrapper)
	return wrapper
}

/**
 * An error as the API reports it, with the HTTP status.
 *
 * @param status - The HTTP status
 * @param message - The server's explanation
 */
function apiError(status: number, message: string): ApiError {
	const cause = new AxiosError(message, 'ERR', undefined, undefined, { status, statusText: '', data: {}, headers: {}, config: { headers: new AxiosHeaders() } })
	return new ApiError(message, null, { cause })
}

/**
 * @param text - The button text
 */
function bodyButton(text: string): HTMLButtonElement | undefined {
	return [...document.body.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)
}

describe('EventItem', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.activity = activity({ questions: [securityEvent(1, { asks: true, canConfirm: true })] })
		personal.manage = { devices: 0, networks: 0, otherBrowsers: 0 }
		vi.mocked(fetchActivity).mockResolvedValue(activity())
		vi.mocked(fetchOverview).mockResolvedValue(overview({ status: { level: 'ok', headline: 'Refreshed', items: [] } }))
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(confirmEvent).mockReset()
		vi.mocked(denyEvent).mockReset()
		vi.mocked(showError).mockReset()
		vi.mocked(showSuccess).mockReset()
		document.body.innerHTML = ''
	})

	test('asks "Was this you?" and has what happened one click away', async () => {
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		expect(wrapper.get('h4').text()).toBe('Someone entered your password but failed the second factor 1')
		expect(wrapper.text()).toContain('203.0.113.7')
		expect(wrapper.get('[data-test="question"]').attributes('aria-labelledby')).toBe(wrapper.get('h4').attributes('id'))
		const toggle = wrapper.get('[data-test="toggle"] button')
		expect(toggle.attributes('aria-expanded')).toBe('false')
		await toggle.trigger('click')
		expect(toggle.attributes('aria-expanded')).toBe('true')
		const details = wrapper.get('[data-test="details"]')
		expect(details.text()).toContain('What Nextcloud did')
		expect(details.text()).toContain('The suspicious session was ended.')
		expect(details.text()).toContain('from the address 203.0.113.7')
	})

	test('confirms after the password', async () => {
		const answered = securityEvent(1, { asks: true, canConfirm: false, verdict: 'confirmed', verdictAt: 1792580400 })
		vi.mocked(confirmEvent).mockResolvedValue(answered)
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()
		expect(confirmEvent).toHaveBeenCalledWith(1)
		expect(showSuccess).toHaveBeenCalled()
		expect(personal.activity?.questions).toEqual([])
		expect(personal.manage.networks).toBe(1)
		expect(personal.overview?.status.headline).toBe('Refreshed')
	})

	test('does nothing when the password dialog is closed', async () => {
		vi.mocked(confirmEvent).mockRejectedValue(new PasswordConfirmationCancelledError())
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()
		expect(showError).not.toHaveBeenCalled()
		expect(personal.activity?.questions).toHaveLength(1)
		expect(wrapper.find('[data-test="confirm"]').exists()).toBe(true)
	})

	test('offers "Yes" also where this session cannot say it, and explains why instead of sending it', async () => {
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: false }))
		expect(wrapper.findAll('[data-test="question"] button').map((b) => b.text())).toEqual(['Yes, it was me', 'No, it was not me'])
		expect(document.body.textContent).not.toContain('Answer from another device')
		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()
		expect(confirmEvent).not.toHaveBeenCalled()
		expect(document.body.textContent).toContain('Answer from another device')
	})

	test('turns a refusal of the server into the same explanation', async () => {
		vi.mocked(confirmEvent).mockRejectedValue(apiError(403, 'For your safety, "Yes, it was me" cannot be answered from the session this event is about.'))
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()
		expect(document.body.textContent).toContain('Answer from another device')
		expect(showError).not.toHaveBeenCalled()
		vi.mocked(confirmEvent).mockClear()
		await wrapper.get('[data-test="confirm"]').trigger('click')
		expect(confirmEvent).not.toHaveBeenCalled()
	})

	test('reloads the list when the event was answered elsewhere', async () => {
		vi.mocked(confirmEvent).mockRejectedValue(apiError(409, 'This event was answered already.'))
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		await wrapper.get('[data-test="confirm"]').trigger('click')
		await flushPromises()
		expect(showError).toHaveBeenCalledWith('This event was answered already.')
		expect(wrapper.emitted('stale')).toHaveLength(1)
	})

	test('"No" explains the consequences first and then answers', async () => {
		const answered = securityEvent(1, { asks: true, verdict: 'denied', verdictAt: 1792580400 })
		vi.mocked(denyEvent).mockResolvedValue(answered)
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: true }))
		await wrapper.get('[data-test="deny"]').trigger('click')
		await flushPromises()
		expect(denyEvent).not.toHaveBeenCalled()
		expect(document.body.textContent).toContain('block the address it came from and tell your administrators')
		bodyButton('Cancel')!.click()
		await flushPromises()
		expect(denyEvent).not.toHaveBeenCalled()

		await wrapper.get('[data-test="deny"]').trigger('click')
		await flushPromises()
		bodyButton('It was not me')!.click()
		await flushPromises()
		expect(denyEvent).toHaveBeenCalledWith(1)
		expect(personal.activity?.questions).toEqual([])
		expect(fetchActivity).toHaveBeenCalled()
	})

	test('"No" from a session that proved only the password keeps the question open', async () => {
		vi.mocked(denyEvent).mockResolvedValue(securityEvent(1, { asks: true, canConfirm: false }))
		const wrapper = mountItem(securityEvent(1, { asks: true, canConfirm: false }))
		expect(wrapper.find('[data-test="told-only"]').exists()).toBe(false)
		await wrapper.get('[data-test="deny"]').trigger('click')
		await flushPromises()
		bodyButton('It was not me')!.click()
		await flushPromises()
		expect(denyEvent).toHaveBeenCalledWith(1)
		expect(personal.activity?.questions).toHaveLength(1)
		expect(showSuccess).not.toHaveBeenCalled()
		expect(wrapper.get('[data-test="told-only"]').text()).toContain('answer "No" again after a login with your second factor')
		expect(wrapper.find('[data-test="deny"]').exists()).toBe(false)
	})
})
