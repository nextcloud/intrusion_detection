/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import SettingsGroup from './SettingsGroup.vue'

const setting: GlobalSetting = { name: 'ban_level1_duration', type: 'duration', default: 14400, min: 300, max: 7776000, choices: [], value: 14400, label: 'First block', help: '', unit: '', group: 'escalation' }

describe('a group of global settings', () => {
	test('shows its fields', () => {
		const wrapper = mount(SettingsGroup, { props: { settings: [setting] } })
		expect(wrapper.text()).toContain('First block')
	})

	test('puts its fields behind a toggle when it has a collapsed label', async () => {
		const wrapper = mount(SettingsGroup, {
			props: { settings: [setting], collapsedLabel: 'Change the durations' },
			slots: { default: () => 'The sentence' },
		})
		expect(wrapper.text()).toContain('The sentence')
		expect(wrapper.text()).not.toContain('First block')
		const toggle = wrapper.get('[data-test="settings-fields"] button')
		expect(toggle.text()).toContain('Change the durations')
		await toggle.trigger('click')
		expect(wrapper.text()).toContain('First block')
	})
})
