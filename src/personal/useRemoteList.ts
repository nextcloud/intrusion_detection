/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Ref } from 'vue'

import { ref } from 'vue'
import { errorMessage } from '../services/api.ts'
import { logger } from '../services/logger.ts'

/**
 * A list loaded from the personal API: null while loading, or the error
 * to show with a retry button.
 *
 * @param fetch - Loads the list
 * @param failure - What to say when it could not be loaded
 */
export function useRemoteList<T>(fetch: () => Promise<T[]>, failure: () => string): {
	items: Ref<T[] | null>
	error: Ref<string | null>
	load: () => Promise<void>
} {
	const items = ref<T[] | null>(null) as Ref<T[] | null>
	const error = ref<string | null>(null)

	/**
	 * Load the list; the previous one stays visible while it reloads.
	 */
	async function load(): Promise<void> {
		error.value = null
		try {
			items.value = await fetch()
		} catch (e) {
			logger.error('Could not load a list of the security section', { error: e })
			error.value = errorMessage(e, failure())
		}
	}

	return { items, error, load }
}
