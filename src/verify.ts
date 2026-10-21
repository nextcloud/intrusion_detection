/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { startPolling } from './verify/poll.ts'

/**
 * The waiting page of a login that an administrator must approve: ask the
 * status endpoint every few seconds and continue once it was decided.
 * Without this script the page works too, with its "Check now" button.
 */
document.addEventListener('DOMContentLoaded', () => {
	const element = document.querySelector<HTMLElement>('[data-ids-poll]')
	if (element) {
		startPolling(element)
	}
})
