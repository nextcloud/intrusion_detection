/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Param } from '../types.ts'

import { describe, expect, test } from 'vitest'
import { nextTick, ref } from 'vue'
import { ApiError } from '../services/api.ts'
import { useParamDraft } from './useParamDraft.ts'

/**
 * @param name - The setting
 * @param value - Its saved value
 */
function param(name: string, value: number | string[]): Param {
	return { name, type: Array.isArray(value) ? 'string_list' : 'int', default: value, min: 1, max: 100, choices: [], value, label: name, help: '', unit: '' }
}

describe('useParamDraft', () => {
	test('collects the valid changes and reports invalid input at its field', () => {
		const params = ref([param('limit', 10), param('names', ['a', 'b'])])
		const form = useParamDraft(() => params.value)
		form.draft.limit = 20
		form.draft.names = ['b', 'a']
		expect(form.changed.value).toEqual(['limit'])
		expect(form.changes()).toEqual({ limit: 20 })
		form.draft.limit = 500
		expect(form.hasErrors.value).toBe(true)
		expect(form.errors.value.limit).toBeTruthy()
		expect(form.changed.value).toEqual([])
	})

	test('unsaved edits survive when the saved settings change', async () => {
		const params = ref([param('limit', 10), param('other', 5)])
		const form = useParamDraft(() => params.value)
		form.draft.limit = 20
		params.value = [param('limit', 10), param('other', 6)]
		await nextTick()
		expect(form.draft.limit).toBe(20)
		expect(form.draft.other).toBe(6)
		form.discard()
		expect(form.draft.limit).toBe(10)
	})

	test('shows a refusal of the server at its field until the next try', () => {
		const form = useParamDraft(() => [param('limit', 10)])
		expect(form.showAtField(new ApiError('Too high', 'limit'))).toBe(true)
		expect(form.errors.value.limit).toBe('Too high')
		expect(form.showAtField(new ApiError('Elsewhere', 'other'))).toBe(false)
		form.clearServerErrors()
		expect(form.errors.value.limit).toBeNull()
	})
})
