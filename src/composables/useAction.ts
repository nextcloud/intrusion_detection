/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Ref } from 'vue'

import { showError, showSuccess } from '@nextcloud/dialogs'
import { ref } from 'vue'
import { errorMessage, isCancelled } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { useAnnouncer } from './useAnnouncer.ts'

export interface ActionOptions<T> {
	/** What to tell when it worked; gets the result */
	done?: string | ((result: T) => string)
	/** What to say when it failed and the server did not explain why */
	fallback: string
	/** Tell the success in a toast as well (a toast is read out, so it is not announced again) */
	toast?: boolean
	/** Keep the failure in `error` instead of a toast, for an error note (which is read out by itself) */
	inline?: boolean
	/** Shows a failure itself, e.g. as the message of one field; returns whether it did. It is announced then. */
	handle?: (error: unknown) => boolean
}

/**
 * Runs the writes of a component: the busy state for its buttons, the
 * message when it worked, and the error when it did not. A closed password
 * dialog is no error. Every message reaches screen readers exactly once:
 * toasts and error notes are read out by themselves, the rest is announced.
 */
export function useAction(): {
	/** What runs, e.g. "save" or "lift:42"; null when nothing does */
	busy: Ref<string | null>
	/** The failure of the last run with `inline` */
	error: Ref<string | null>
	run: <T>(key: string, action: () => Promise<T>, options: ActionOptions<T>) => Promise<boolean>
} {
	const busy = ref<string | null>(null)
	const error = ref<string | null>(null)
	const { announce } = useAnnouncer()

	/**
	 * @param key - What runs, for the busy state
	 * @param action - The work
	 * @param options - Messages and how a failure is shown
	 * @return whether it worked
	 */
	async function run<T>(key: string, action: () => Promise<T>, options: ActionOptions<T>): Promise<boolean> {
		busy.value = key
		error.value = null
		try {
			const result = await action()
			const done = typeof options.done === 'function' ? options.done(result) : options.done
			if (done !== undefined && done !== '') {
				if (options.toast) {
					showSuccess(done)
				} else {
					announce(done)
				}
			}
			return true
		} catch (failure) {
			if (isCancelled(failure)) {
				return false
			}
			logger.error(`Action "${key}" failed`, { error: failure })
			const message = errorMessage(failure, options.fallback)
			if (options.handle?.(failure)) {
				announce(message)
			} else if (options.inline) {
				error.value = message
			} else {
				showError(message)
			}
			return false
		} finally {
			if (busy.value === key) {
				busy.value = null
			}
		}
	}

	return { busy, error, run }
}
