/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import LearningSection from './LearningSection.vue'
import { state } from '../../store.ts'
import { makeStatus } from '../../tests/fixtures.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

/**
 * @param name - The setting
 * @param group - Its group
 */
function bool(name: string, group: string): GlobalSetting {
	return { name, type: 'bool', default: true, min: null, max: null, choices: [], value: true, label: `Label of ${name}`, help: '', unit: '', group }
}

describe('the learning mode and other settings', () => {
	beforeEach(() => {
		state.status = makeStatus()
		state.settings = [
			bool('protection_enabled', 'master'),
			bool('learning_decoys_act', 'learning'),
			bool('admin_change_require_approval', 'approvals'),
		]
	})

	test('learning mode, the master switch, the learning settings, every other setting, export and reset', () => {
		const wrapper = mount(LearningSection)
		expect(wrapper.text()).toContain('Learning mode')
		expect(wrapper.text()).toContain('Start protecting now')
		expect(wrapper.find('#settings-other').text()).toContain('Intrusion detection is on')
		expect(wrapper.text()).toContain('Label of learning_decoys_act')
		expect(wrapper.text()).toContain('Label of admin_change_require_approval')
		const support = wrapper.get('#settings-support').text()
		expect(support).toContain('Export settings as JSON')
		expect(support).toContain('Reset all settings to defaults')
	})

	test('learning mode says what still blocks', () => {
		const text = mount(LearningSection).text()
		expect(text).toContain('Checks set to Protect only record what they would block; earlier blocks, blocks you add by hand, a user\'s "No, it was not me" and, unless you switched it off, decoys still block.')
		expect(text).toContain('Alerts are still sent.')
	})
})
