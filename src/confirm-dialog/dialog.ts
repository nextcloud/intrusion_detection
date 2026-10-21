/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * The answer of a sensitive action that needs a fresh confirmation:
 * `403 {"error": "confirmation_required", "url": …, "dialog": {…}}`, or the
 * same inside the data of an OCS answer. The server sends the dialog's
 * texts in the user's language, so this script needs no translations.
 */
export interface Refusal {
	url: string
	dialog: { title: string, text: string, confirm: string, cancel: string }
}

/** The dialog's look, from the theme's variables only; centred, as core's reset takes the margin away */
const STYLE = '.ids-confirm{box-sizing:border-box;width:min(420px,100vw - 32px);margin:auto;padding:24px;border:1px solid var(--color-border);border-radius:var(--border-radius-container);background:var(--color-main-background);color:var(--color-main-text)}'
	+ '.ids-confirm::backdrop{background:#0006}.ids-confirm h2{margin:0;font-size:20px}.ids-confirm p{margin:8px 0 24px}'
	+ '.ids-confirm div{display:flex;flex-wrap:wrap;justify-content:end;gap:8px}'

/**
 * The refusal in a 403 answer's body, if it is one. Its URL must be the
 * confirm page of this server.
 *
 * @param status - The HTTP status
 * @param body - The body as text
 */
export function parseRefusal(status: number, body: unknown): Refusal | null {
	if (status !== 403) {
		return null
	}
	try {
		const json = JSON.parse(body as string)
		const data = json.ocs?.data ?? json
		const url = new URL(data.url, location.href)
		return data.error === 'confirmation_required' && data.dialog?.confirm && url.origin === location.origin && url.pathname.includes('/apps/intrusion_detection/confirm')
			? { url: url.href, dialog: data.dialog }
			: null
	} catch {
		return null
	}
}

/**
 * The confirm page, which returns to the page the user is on.
 *
 * @param url - The confirm page from the refusal
 */
export function confirmUrl(url: string): string {
	const target = new URL(url)
	target.searchParams.set('redirect_url', location.pathname + location.search)
	return target.href
}

/**
 * Ask the user to confirm: a modal dialog with the reason, Cancel and
 * Confirm. Confirm opens the confirm page, which comes back here; the user
 * then does the action again, as the dialog says. One dialog at a time.
 *
 * @param refusal - What the server answered
 * @param refusal.url - The confirm page
 * @param refusal.dialog - The dialog's texts
 */
export function showDialog({ url, dialog: text }: Refusal): void {
	if (document.querySelector('.ids-confirm')) {
		return
	}
	const dialog = document.createElement('dialog')
	dialog.className = 'ids-confirm'
	dialog.setAttribute('aria-labelledby', 'ids-confirm')
	dialog.innerHTML = `<style>${STYLE}</style><h2 id="ids-confirm"></h2><p></p><div><button></button><button class="primary"></button></div>`
	const [cancel, confirm] = dialog.querySelectorAll('button')
	dialog.querySelector('h2')!.textContent = text.title
	dialog.querySelector('p')!.textContent = text.text
	cancel!.textContent = text.cancel
	confirm!.textContent = text.confirm
	cancel!.onclick = () => dialog.close()
	confirm!.onclick = () => location.assign(confirmUrl(url))
	dialog.onclose = () => dialog.remove()
	document.body.append(dialog)
	dialog.showModal()
	confirm!.focus()
}

/**
 * Show the dialog for a refusal, if the answer is one.
 *
 * @param status - The HTTP status
 * @param body - The body as text
 */
function check(status: number, body: unknown): void {
	const refusal = parseRefusal(status, body)
	if (refusal) {
		showDialog(refusal)
	}
}

/**
 * Watch the answers of every request of the page, whichever copy of
 * `@nextcloud/axios` (or `fetch`) made it: each app bundles its own, but
 * they all go through XMLHttpRequest or fetch. Requests are not changed;
 * their callers still get the 403.
 */
export function install(): void {
	const send = XMLHttpRequest.prototype.send
	XMLHttpRequest.prototype.send = function(this: XMLHttpRequest, ...args) {
		this.addEventListener('loadend', () => check(this.status, typeof this.response === 'string' ? this.response : JSON.stringify(this.response)))
		return send.apply(this, args)
	}
	const fetch = window.fetch
	window.fetch = async (...args) => {
		const response = await fetch(...args)
		if (response.status === 403) {
			response.clone().text().then((body) => check(403, body), () => undefined)
		}
		return response
	}
}
