/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { onBeforeUnmount, ref } from 'vue'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'
import { useAnnouncer } from './useAnnouncer.ts'

/**
 * Copy text to the clipboard, with a short "Copied" state for the button
 * and an announcement for screen readers.
 */
export function useCopy() {
	const copied = ref(false)
	const failed = ref(false)
	const { announce } = useAnnouncer()
	let timer: ReturnType<typeof setTimeout> | undefined

	onBeforeUnmount(() => clearTimeout(timer))

	/**
	 * @param text - What to copy
	 * @param done - What to announce when it worked
	 */
	async function copy(text: string, done: string = t(APP_ID, 'Copied')): Promise<boolean> {
		clearTimeout(timer)
		try {
			await navigator.clipboard.writeText(text)
			copied.value = true
			failed.value = false
			announce(done)
			timer = setTimeout(() => {
				copied.value = false
			}, 2000)
			return true
		} catch {
			failed.value = true
			announce(t(APP_ID, 'Could not copy. Select the text and copy it by hand.'))
			return false
		}
	}

	return { copied, failed, copy }
}
