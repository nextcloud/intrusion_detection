/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import NcSelect from '@nextcloud/vue/components/NcSelect'
import SelectField from './SelectField.vue'

const options = [{ value: 'refuse', label: 'Refuse the login' }, { value: 'allow_notify', label: 'Allow it and tell the user' }]

describe('a select with the Nextcloud look', () => {
	test('shows its label above and the label of the chosen value, never the raw value', () => {
		const wrapper = mount(SelectField, { props: { modelValue: 'allow_notify', options, label: 'If nothing can confirm' } })
		expect(wrapper.get('label').text()).toBe('If nothing can confirm')
		expect(wrapper.get('label').attributes('for')).toBe(wrapper.findComponent(NcSelect).props('inputId'))
		expect(wrapper.text()).toContain('Allow it and tell the user')
		expect(wrapper.text()).not.toContain('allow_notify')
	})

	test('a long chosen label is cut at the end of its field, the full label on hover', () => {
		const wrapper = mount(SelectField, { props: { modelValue: 'allow_notify', options, label: 'If nothing can confirm' } })
		const selected = wrapper.get('[title="Allow it and tell the user"]')
		expect(selected.text()).toBe('Allow it and tell the user')
		expect(selected.classes().some((name) => name.includes('select__selected'))).toBe(true)
	})

	test('passes on the value of the chosen option', async () => {
		const wrapper = mount(SelectField, { props: { modelValue: 'refuse', options, label: 'If nothing can confirm' } })
		wrapper.findComponent(NcSelect).vm.$emit('update:modelValue', options[1])
		expect(wrapper.emitted('update:modelValue')).toEqual([['allow_notify']])
	})

	test('a hidden label still names the field for screen readers', () => {
		const wrapper = mount(SelectField, { props: { modelValue: 'refuse', options, label: 'Unit', hideLabel: true } })
		expect(wrapper.find('label').exists()).toBe(false)
		expect(wrapper.findComponent(NcSelect).props('ariaLabelCombobox')).toBe('Unit')
	})
})
