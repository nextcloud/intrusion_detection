/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ConfirmationOutcome, ConfirmationPolicy, GlobalSetting } from '../../types.ts'

import { showSuccess } from '@nextcloud/dialogs'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import SelectField from '../common/SelectField.vue'
import PolicyTable from './PolicyTable.vue'
import { updateSettings } from '../../services/api.ts'
import { state } from '../../store.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateSettings: vi.fn(),
}))

const outcomes: ConfirmationOutcome[] = [
	{ id: 'refuse', label: 'Refuse the login', description: 'The person sees a reference.' },
	{ id: 'allow_notify', label: 'Allow it and tell the user and you', description: 'The login goes ahead.' },
	{ id: 'allow_force_change', label: 'Allow it and require a new password', description: 'A new password first.' },
]

const policies: ConfirmationPolicy[] = [
	{ id: 'flagged_source', label: 'Login from an attacking address', why: 'The address was part of an attack.', default: 'refuse', outcome: 'refuse', setting: 'step_up_no_method_flagged_source', knownDevice: true, knownDeviceAllowed: true },
	{ id: 'sprayed_password', label: 'Login with a sprayed password', why: 'Attackers are trying it.', default: 'refuse', outcome: 'refuse', setting: 'step_up_no_method_sprayed_password', knownDevice: false, knownDeviceAllowed: false },
	{ id: 'breached_password', label: 'Login with a breached password', why: 'It must change anyway.', default: 'allow_force_change', outcome: 'allow_notify', setting: 'step_up_no_method_breached_password', knownDevice: false, knownDeviceAllowed: false },
]

const knownDeviceSetting: GlobalSetting = { name: 'step_up_known_device_ok_for', type: 'string_list', default: [], min: null, max: null, choices: [], value: ['flagged_source', 'risk_high'], label: '', help: '', unit: '', group: 'step_up' }

describe('PolicyTable', () => {
	beforeEach(() => {
		state.settings = [knownDeviceSetting]
		vi.mocked(updateSettings).mockImplementation(async (values) => ({ settings: [{ ...knownDeviceSetting, value: values.step_up_known_device_ok_for ?? knownDeviceSetting.value }], templates: {} }))
	})

	afterEach(() => {
		vi.mocked(updateSettings).mockReset()
		vi.mocked(showSuccess).mockReset()
	})

	test('shows every reason with labelled choices, never raw values', () => {
		const wrapper = mount(PolicyTable, { props: { policies, outcomes } })
		const rows = wrapper.findAll('tbody tr')
		expect(rows).toHaveLength(3)
		const select = (row: number) => rows[row]!.findComponent(SelectField)
		expect(select(0).props('options').map((o: { label: string }) => o.label)).toEqual(['Refuse the login (default)', 'Allow it and tell the user and you', 'Allow it and require a new password'])
		expect(select(0).props('label')).toContain('Login from an attacking address')
		expect(wrapper.text()).not.toContain('allow_notify')
		expect(select(2).props('modelValue')).toBe('allow_notify')
		expect(rows[2]!.text()).toContain('Allow it and tell the user and you')
		expect(rows[2]!.text()).toContain('Default: Allow it and require a new password.')
		expect(rows[2]!.text()).toContain('The login goes ahead.')
	})

	test('a remembered device can never confirm a login whose password is at risk', () => {
		const wrapper = mount(PolicyTable, { props: { policies, outcomes } })
		const rows = wrapper.findAll('tbody tr')
		expect(rows[0]!.find('input[type="checkbox"]').exists()).toBe(true)
		expect(rows[1]!.find('input[type="checkbox"]').exists()).toBe(false)
		expect(rows[1]!.text()).toContain('Never: the password itself is at risk')
	})

	test('choosing an outcome saves it at once', async () => {
		const wrapper = mount(PolicyTable, { props: { policies, outcomes } })
		wrapper.findAll('tbody tr')[0]!.findComponent(SelectField).vm.$emit('update:modelValue', 'allow_notify')
		await flushPromises()
		expect(updateSettings).toHaveBeenCalledWith({ step_up_no_method_flagged_source: 'allow_notify' })
		expect(showSuccess).toHaveBeenCalled()
	})

	test('the device switch keeps the other reasons in the list', async () => {
		const wrapper = mount(PolicyTable, { props: { policies, outcomes } })
		await wrapper.findAll('tbody tr')[0]!.get('input[type="checkbox"]').setValue(false)
		await flushPromises()
		expect(updateSettings).toHaveBeenCalledWith({ step_up_known_device_ok_for: ['risk_high'] })
		expect(state.settings[0]!.value).toEqual(['risk_high'])
	})
})
