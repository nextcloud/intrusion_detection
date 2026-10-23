/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Check, Mode } from '../types.ts'

import { computed, ref, watch } from 'vue'
import { modeLabel, saveCheck } from '../store.ts'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'
import { useAction } from './useAction.ts'

/**
 * The Off / Observe / Protect choice of a check: saved at once,
 * optimistically, and put back when saving fails.
 *
 * @param check - The check, as the server has it
 */
export function useCheckMode(check: () => Check) {
	const mode = ref<Mode>(check().mode.configured)
	const { busy, run } = useAction()
	const saving = computed(() => busy.value !== null)

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
		const saved = await run('mode', () => saveCheck(current.id, { mode: value }), {
			done: t(APP_ID, 'Saved: {check} is set to {mode}.', { check: current.texts.name, mode: modeLabel(value) }),
			fallback: t(APP_ID, 'The mode could not be changed. Please try again.'),
		})
		if (!saved) {
			mode.value = previous
		}
	}

	return { mode, saving, missingRequirement, change }
}
