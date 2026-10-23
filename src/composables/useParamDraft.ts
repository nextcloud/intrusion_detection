/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Choice, Param, ParamType, ParamValue } from '../types.ts'

import { computed, reactive, watch } from 'vue'
import { ApiError } from '../services/api.ts'
import { globalChoices, globalTypes, globalValues } from '../store.ts'
import { validateParam } from '../utils/validate.ts'

/**
 * Whether two values are the same; lists in any order.
 *
 * @param a - A value
 * @param b - Another value
 */
function sameValue(a: unknown, b: unknown): boolean {
	return Array.isArray(a) && Array.isArray(b) ? sameList(a.map(String), b.map(String)) : a === b
}

/**
 * @param a - A list
 * @param b - Another list
 */
export function sameList(a: string[], b: string[]): boolean {
	return a.length === b.length && a.every((item) => b.includes(item))
}

/**
 * The form of a set of settings: what is typed, checked as it is typed,
 * and what the server refused. Unsaved edits survive when the saved
 * settings change, e.g. after another form saved.
 *
 * @param params - The settings as the server has them
 */
export function useParamDraft(params: () => Param[]) {
	const draft = reactive<Record<string, unknown>>({})
	const serverErrors = reactive<Record<string, string>>({})

	watch(params, (current, old) => {
		for (const param of current) {
			const before = old?.find((p) => p.name === param.name)
			if (before === undefined || !(param.name in draft) || sameValue(draft[param.name], before.value)) {
				draft[param.name] = param.value
			}
		}
	}, { immediate: true })

	const validation = computed(() => Object.fromEntries(params().map((param) => [param.name, validateParam(param, draft[param.name])])))

	/** The message of each field: what the check of the typed value found, else what the server said */
	const errors = computed<Record<string, string | null>>(() => Object.fromEntries(params().map((param) => [
		param.name,
		validation.value[param.name]?.error ?? serverErrors[param.name] ?? null,
	])))

	/** The settings whose valid typed value differs from the saved one */
	const changed = computed(() => params()
		.filter((param) => {
			const value = validation.value[param.name]?.value
			return value !== undefined && !sameValue(value, param.value)
		})
		.map((param) => param.name))

	const hasErrors = computed(() => params().some((param) => validation.value[param.name]?.error))

	/** The live values: what is typed where valid, the saved value elsewhere, and the global settings */
	const values = computed<Record<string, ParamValue>>(() => ({
		...globalValues.value,
		...Object.fromEntries(params().map((param) => [param.name, validation.value[param.name]?.value ?? param.value])),
	}))
	const types = computed<Record<string, ParamType>>(() => ({ ...globalTypes.value, ...Object.fromEntries(params().map((p) => [p.name, p.type])) }))
	const choices = computed<Record<string, Choice[]>>(() => ({ ...globalChoices.value, ...Object.fromEntries(params().map((p) => [p.name, p.choices])) }))

	/**
	 * The changed values, to save.
	 */
	function changes(): Record<string, ParamValue> {
		return Object.fromEntries(changed.value.map((name) => [name, validation.value[name]!.value!]))
	}

	/**
	 * Take values as they are now, e.g. as saved or reset, into the form.
	 *
	 * @param saved - The settings
	 */
	function take(saved: Param[]): void {
		for (const param of saved) {
			draft[param.name] = param.value
		}
	}

	/**
	 * Forget what the server said about earlier values.
	 */
	function clearServerErrors(): void {
		Object.keys(serverErrors).forEach((key) => delete serverErrors[key])
	}

	/**
	 * Show a refusal of the server at its field, when it is about one of these settings.
	 *
	 * @param error - What saving threw
	 * @return whether it was shown at a field
	 */
	function showAtField(error: unknown): boolean {
		if (error instanceof ApiError && error.param !== null && params().some((p) => p.name === error.param)) {
			serverErrors[error.param] = error.message
			return true
		}
		return false
	}

	/**
	 * Throw away the unsaved changes.
	 */
	function discard(): void {
		take(params())
		clearServerErrors()
	}

	return { draft, errors, changed, hasErrors, values, types, choices, changes, take, discard, clearServerErrors, showAtField }
}
