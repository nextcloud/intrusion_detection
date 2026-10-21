/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

export type ApprovalStatus = 'none' | 'pending' | 'approved' | 'rejected' | 'expired'

/** Statuses after which the page continues: the server decides what happens next */
const DECIDED: ApprovalStatus[] = ['none', 'approved', 'rejected', 'expired']

/**
 * Ask the status endpoint of the waiting page.
 *
 * @param url - The status endpoint
 * @param fetcher - The fetch function, replaceable in tests
 */
export async function fetchStatus(url: string, fetcher: typeof fetch = fetch): Promise<ApprovalStatus | null> {
	try {
		const response = await fetcher(url, { credentials: 'same-origin', headers: { Accept: 'application/json' }, cache: 'no-store' })
		if (!response.ok) {
			return null
		}
		const data = await response.json() as { status?: unknown }
		return typeof data.status === 'string' && ['none', 'pending', 'approved', 'rejected', 'expired'].includes(data.status) ? data.status as ApprovalStatus : null
	} catch {
		return null
	}
}

/**
 * Poll until an administrator decided, then submit the page's continue
 * form, which carries the "Remember this device" choice. The status line
 * is a live region, so screen readers hear the change.
 *
 * @param element - The element with `data-ids-poll` (the status URL), `data-ids-poll-interval` (seconds) and `data-ids-poll-form` (the id of the form)
 * @param fetcher - The fetch function, replaceable in tests
 * @return A function that stops polling
 */
export function startPolling(element: HTMLElement, fetcher: typeof fetch = fetch): () => void {
	const url = element.dataset.idsPoll ?? ''
	const interval = Math.max(5, Number(element.dataset.idsPollInterval ?? '10')) * 1000
	const form = document.getElementById(element.dataset.idsPollForm ?? '') as HTMLFormElement | null
	const status = element.querySelector<HTMLElement>('[data-ids-poll-status]')
	let timer: ReturnType<typeof setTimeout> | undefined
	let stopped = false

	const say = (text: string | undefined) => {
		if (status && text && status.textContent !== text) {
			status.textContent = text
		}
	}

	const check = async (): Promise<void> => {
		timer = undefined
		const result = await fetchStatus(url, fetcher)
		if (stopped) {
			return
		}
		if (result !== null && DECIDED.includes(result)) {
			stopped = true
			say(status?.dataset.idsTextDecided)
			form?.submit()
			return
		}
		say(result === null ? status?.dataset.idsTextOffline : status?.dataset.idsTextPending)
		if (timer === undefined) {
			timer = setTimeout(() => {
				void check()
			}, interval)
		}
	}

	const onVisible = () => {
		if (document.visibilityState === 'visible' && timer !== undefined) {
			clearTimeout(timer)
			timer = undefined
			void check()
		}
	}

	if (url === '' || form === null) {
		return () => {}
	}
	document.addEventListener('visibilitychange', onVisible)
	timer = setTimeout(() => {
		void check()
	}, interval)
	return () => {
		stopped = true
		if (timer !== undefined) {
			clearTimeout(timer)
		}
		document.removeEventListener('visibilitychange', onVisible)
	}
}
