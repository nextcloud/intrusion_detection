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
	test('a whole number is shown with digit groups, like its hint', () => {
		const wrapper = mount(ParamField, { props: { param: param({ value: 200000, default: 200000, max: 1000000 }), modelValue: 200000 } })
		expect((wrapper.get('input').element as HTMLInputElement).value).toBe('200,000')
		expect(wrapper.text()).toContain('default 200,000')
	})
})
