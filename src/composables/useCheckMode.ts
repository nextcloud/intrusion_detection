/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Check, Mode } from '../types.ts'

import { showError } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import { errorMessage, isCancelled, updateCheck } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshStatus, replaceCheck } from '../store.ts'
import { APP_ID } from '../utils/format.ts'
import { useAnnouncer } from './useAnnouncer.ts'

/**
 * @param value - A mode
 */
export function modeLabel(value: Mode): string {
	return { off: t(APP_ID, 'Off'), observe: t(APP_ID, 'Observe'), protect: t(APP_ID, 'Protect') }[value]
}

/**
 * The Off / Observe / Protect choice of a check: saved at once,
 * optimistically, and put back when saving fails.
 *
 * @param check - The check, as the server has it
 */
export function useCheckMode(check: () => Check) {
	const mode = ref<Mode>(check().mode.configured)
	const saving = ref(false)
	const { announce } = useAnnouncer()

	watch(() => check().mode.configured, (configured) => {
		mode.value = configured
	})

	/** A missing requirement allows only Off */
	const missingRequirement = computed(() => check().requirements.find((r) => !r.met) ?? null)

	/**
	 * @param value - The new mode
	 */
	async function change(value: Mode) {
		const current = check()
		const previous = current.mode.configured
		// The radio group may report one choice twice; only a real change is saved.
		if (value === mode.value) {
			return
		}
		mode.value = value
		if (value === previous) {
			return
		}
		saving.value = true
		try {
			replaceCheck(await updateCheck(current.id, { mode: value }))
			announce(t(APP_ID, 'Saved: {check} is set to {mode}.', { check: current.texts.name, mode: modeLabel(value) }))
			refreshStatus()
		} catch (error) {
			mode.value = previous
			if (!isCancelled(error)) {
				logger.error('Could not change the mode', { error })
				const message = errorMessage(error, t(APP_ID, 'The mode could not be changed. Please try again.'))
				showError(message)
				announce(message)
			}
		} finally {
			saving.value = false
		}
	}

	return { mode, saving, missingRequirement, change }
}
