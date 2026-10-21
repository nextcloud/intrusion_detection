/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { fetchStatus, startPolling } from './poll.ts'

/**
 * A fetch that answers with these statuses in turn; `null` fails.
 *
 * @param answers - The statuses
 */
function fetcher(...answers: (string | null)[]) {
	return vi.fn(async () => {
		const status = answers.length > 0 ? answers.shift() : 'pending'
		if (status === null || status === undefined) {
			throw new TypeError('offline')
		}
		return new Response(JSON.stringify({ status, retryAfter: 10 }), { status: 200 })
	}) as unknown as typeof fetch
}

/**
 * The markup of the waiting page.
 */
function page(): { element: HTMLElement, form: HTMLFormElement, status: HTMLElement } {
	document.body.innerHTML = `
		<div data-ids-poll="/apps/intrusion_detection/verify/approval/status" data-ids-poll-interval="10" data-ids-poll-form="ids-approval-continue">
			<p data-ids-poll-status data-ids-text-pending="Waiting" data-ids-text-decided="Decided" data-ids-text-offline="Offline">Waiting</p>
		</div>
		<form id="ids-approval-continue" method="post" action="/continue"><input type="checkbox" name="remember" value="1"></form>`
	const form = document.getElementById('ids-approval-continue') as HTMLFormElement
	form.submit = vi.fn()
	return { element: document.querySelector('[data-ids-poll]')!, form, status: document.querySelector('[data-ids-poll-status]')! }
}

describe('the waiting page script', () => {
	beforeEach(() => {
		vi.useFakeTimers()
	})

	afterEach(() => {
		vi.useRealTimers()
		document.body.innerHTML = ''
	})

	test('reads only known statuses and fails quietly', async () => {
		expect(await fetchStatus('/s', fetcher('approved'))).toBe('approved')
		expect(await fetchStatus('/s', fetcher('anything'))).toBeNull()
		expect(await fetchStatus('/s', fetcher(null))).toBeNull()
		const notFound = vi.fn(async () => new Response('', { status: 403 })) as unknown as typeof fetch
		expect(await fetchStatus('/s', notFound)).toBeNull()
	})

	test('asks every interval and submits the continue form once decided', async () => {
		const { element, form, status } = page()
		const fetch = fetcher('pending', null, 'approved')
		startPolling(element, fetch)

		await vi.advanceTimersByTimeAsync(9_000)
		expect(fetch).not.toHaveBeenCalled()
		await vi.advanceTimersByTimeAsync(1_000)
		expect(fetch).toHaveBeenCalledTimes(1)
		expect(status.textContent).toBe('Waiting')
		expect(form.submit).not.toHaveBeenCalled()

		await vi.advanceTimersByTimeAsync(10_000)
		expect(status.textContent).toBe('Offline')

		await vi.advanceTimersByTimeAsync(10_000)
		expect(form.submit).toHaveBeenCalledTimes(1)
		expect(status.textContent).toBe('Decided')

		await vi.advanceTimersByTimeAsync(60_000)
		expect(fetch).toHaveBeenCalledTimes(3)
	})

	test('a rejected, expired or vanished request also continues: the server says what happens', async () => {
		for (const decided of ['rejected', 'expired', 'none']) {
			const { element, form } = page()
			const stop = startPolling(element, fetcher(decided))
			await vi.advanceTimersByTimeAsync(10_000)
			expect(form.submit).toHaveBeenCalledTimes(1)
			stop()
		}
	})

	test('stops when asked', async () => {
		const { element } = page()
		const fetch = fetcher()
		const stop = startPolling(element, fetch)
		stop()
		await vi.advanceTimersByTimeAsync(60_000)
		expect(fetch).not.toHaveBeenCalled()
	})
})
