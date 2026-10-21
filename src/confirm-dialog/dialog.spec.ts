/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { confirmUrl, install, parseRefusal, showDialog } from './dialog.ts'

const DIALOG = { title: 'Confirm it\'s you', text: 'To do this, confirm it\'s you. You come back to this page afterwards; then do it again.', confirm: 'Confirm', cancel: 'Cancel' }

/**
 * A refusal as the server sends it.
 *
 * @param url - The confirm page
 */
function body(url = '/index.php/apps/intrusion_detection/confirm?redirect_url=%2Fold'): string {
	return JSON.stringify({ error: 'confirmation_required', url, message: 'To do this, confirm it\'s you.', dialog: DIALOG })
}

const dialog = () => document.querySelector<HTMLDialogElement>('dialog.ids-confirm')

describe('the confirm dialog', () => {
	beforeAll(() => {
		// jsdom has no modal dialogs.
		HTMLDialogElement.prototype.showModal ??= function(this: HTMLDialogElement) {
			this.open = true
		}
		HTMLDialogElement.prototype.close ??= function(this: HTMLDialogElement) {
			this.open = false
			this.dispatchEvent(new Event('close'))
		}
	})

	beforeEach(() => {
		window.history.replaceState(null, '', '/index.php/settings/user/security?section=1')
	})

	afterEach(() => {
		dialog()?.remove()
		vi.restoreAllMocks()
	})

	test('a 403 that asks for confirmation is recognised, in JSON and in OCS', () => {
		expect(parseRefusal(403, body())?.url).toBe(location.origin + '/index.php/apps/intrusion_detection/confirm?redirect_url=%2Fold')
		expect(parseRefusal(403, JSON.stringify({ ocs: { meta: { statuscode: 403 }, data: JSON.parse(body()) } }))?.dialog).toEqual(DIALOG)
	})

	test('anything else is left alone', () => {
		expect(parseRefusal(200, body())).toBeNull()
		expect(parseRefusal(403, JSON.stringify({ error: 'step_up_required' }))).toBeNull()
		expect(parseRefusal(403, 'confirmation_required, but not JSON')).toBeNull()
		expect(parseRefusal(403, undefined)).toBeNull()
		expect(parseRefusal(403, body('https://evil.example/apps/intrusion_detection/confirm')), 'another server').toBeNull()
		expect(parseRefusal(403, body('/index.php/apps/files/')), 'another page').toBeNull()
		expect(parseRefusal(403, JSON.stringify({ error: 'confirmation_required', url: '/apps/intrusion_detection/confirm' })), 'no texts').toBeNull()
	})

	test('the confirm page returns to the page the user is on', () => {
		const url = new URL(confirmUrl(location.origin + '/index.php/apps/intrusion_detection/confirm?redirect_url=%2Fold'))
		expect(url.pathname).toBe('/index.php/apps/intrusion_detection/confirm')
		expect(url.searchParams.get('redirect_url')).toBe('/index.php/settings/user/security?section=1')
	})

	test('the dialog says what to do, and Confirm goes to the confirm page', () => {
		const assign = vi.fn()
		vi.spyOn(window, 'location', 'get').mockReturnValue({ ...window.location, assign, origin: window.location.origin, pathname: window.location.pathname, search: window.location.search, href: window.location.href } as Location)
		showDialog(parseRefusal(403, body())!)
		const shown = dialog()!
		expect(shown.open).toBe(true)
		expect(shown.getAttribute('aria-labelledby')).toBe('ids-confirm')
		expect(shown.querySelector('h2')!.textContent).toBe(DIALOG.title)
		expect(shown.querySelector('p')!.textContent).toBe(DIALOG.text)
		const [cancel, confirm] = shown.querySelectorAll('button')
		expect(cancel!.textContent).toBe('Cancel')
		expect(confirm!.textContent).toBe('Confirm')
		expect(document.activeElement).toBe(confirm)
		confirm!.click()
		expect(assign).toHaveBeenCalledOnce()
		expect(new URL(assign.mock.calls[0]![0]).searchParams.get('redirect_url')).toBe('/index.php/settings/user/security?section=1')
	})

	test('Cancel closes it, and only one dialog is open at a time', () => {
		showDialog(parseRefusal(403, body())!)
		showDialog(parseRefusal(403, body())!)
		expect(document.querySelectorAll('dialog.ids-confirm')).toHaveLength(1)
		dialog()!.querySelector('button')!.click()
		expect(dialog()).toBeNull()
	})

	test('texts from the server are shown as text, never as markup', () => {
		showDialog({ url: location.origin + '/apps/intrusion_detection/confirm', dialog: { ...DIALOG, title: '<img src=x onerror=alert(1)>' } })
		expect(dialog()!.querySelector('img')).toBeNull()
		expect(dialog()!.querySelector('h2')!.textContent).toBe('<img src=x onerror=alert(1)>')
	})

	describe('watching requests', () => {
		let originalSend: typeof XMLHttpRequest.prototype.send
		let originalFetch: typeof window.fetch

		beforeEach(() => {
			originalSend = XMLHttpRequest.prototype.send
			originalFetch = window.fetch
		})

		afterEach(() => {
			XMLHttpRequest.prototype.send = originalSend
			window.fetch = originalFetch
		})

		/**
		 * Install the script over a fake XMLHttpRequest that answers at once.
		 *
		 * @param status - The answer's status
		 * @param response - The answer
		 */
		function xhr(status: number, response: unknown): XMLHttpRequest {
			XMLHttpRequest.prototype.send = function(this: XMLHttpRequest) {
				Object.defineProperty(this, 'status', { value: status })
				Object.defineProperty(this, 'response', { value: response })
				this.dispatchEvent(new ProgressEvent('loadend'))
			}
			install()
			const request = new XMLHttpRequest()
			request.open('POST', '/ocs/v2.php/cloud/users/alice')
			request.send()
			return request
		}

		test('a refused request of @nextcloud/axios (XMLHttpRequest) opens the dialog', () => {
			xhr(403, body())
			expect(dialog()).not.toBeNull()
		})

		test('also when the answer was parsed as JSON already', () => {
			xhr(403, JSON.parse(body()))
			expect(dialog()).not.toBeNull()
		})

		test('other answers open nothing', () => {
			xhr(403, JSON.stringify({ error: 'login_refused' }))
			xhr(200, body())
			expect(dialog()).toBeNull()
		})

		test('a refused fetch opens the dialog, and the caller still gets the 403', async () => {
			window.fetch = vi.fn(async () => new Response(body(), { status: 403 })) as unknown as typeof fetch
			install()
			const response = await window.fetch('/index.php/settings/personal/authtokens', { method: 'POST' })
			expect(response.status).toBe(403)
			await vi.waitFor(() => expect(dialog()).not.toBeNull())
			expect(await response.json()).toMatchObject({ error: 'confirmation_required' })
		})
	})
})
