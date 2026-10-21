/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Param } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import ParamField from './ParamField.vue'

/**
 * @param overrides - Fields to change
 */
function param(overrides: Partial<Param>): Param {
	return { name: 'p', type: 'int', default: 1, min: null, max: null, choices: [], value: 1, label: 'A setting', help: '', unit: '', ...overrides }
}

const wide = (p: Param, value: unknown = p.value) => mount(ParamField, { props: { param: p, modelValue: value } }).attributes('data-wide') === 'true'

describe('the width of a field in a settings grid', () => {
	test('a switch with a description takes the whole row', () => {
		expect(wide(param({ type: 'bool', value: true, default: true, help: 'When nothing happened, a short email says so.' }))).toBe(true)
		expect(wide(param({ type: 'bool', value: true, default: true }))).toBe(false)
	})

	test('lists and fields with a long description take the whole row, short fields one column', () => {
		expect(wide(param({ type: 'string_list', value: [], default: [] }), [])).toBe(true)
		expect(wide(param({ type: 'cidr_list', value: [], default: [] }), [])).toBe(true)
		expect(wide(param({ help: 'x'.repeat(121) }))).toBe(true)
		expect(wide(param({ help: 'Within 10 minutes.' }))).toBe(false)
	})
})
