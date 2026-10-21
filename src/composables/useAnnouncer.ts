/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { ref } from 'vue'

const message = ref('')
let timer: ReturnType<typeof setTimeout> | undefined

/**
 * One polite live region for the whole page: "Saved", "Block lifted" and
 * errors are read out by screen readers without moving the focus.
 */
export function useAnnouncer() {
	return {
		message,
		/**
		 * @param text - What to announce
		 */
		announce(text: string) {
			// Clearing first makes the same text be announced again.
			message.value = ''
			clearTimeout(timer)
			timer = setTimeout(() => {
				message.value = text
			}, 50)
		},
	}
}
