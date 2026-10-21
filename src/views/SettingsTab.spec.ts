/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import SettingsTab from './SettingsTab.vue'

describe('the Settings tab', () => {
	test('has four sections with headings and ids to link to', () => {
		const wrapper = mount(SettingsTab, {
			global: {
				stubs: {
					NotificationsSection: true,
					ConfirmationSection: true,
					PrivacySection: true,
					LearningSection: true,
				},
			},
		})
		const sections = wrapper.findAll('section')
		expect(sections.map((s) => s.attributes('id'))).toEqual(['settings-notifications', 'settings-confirmation', 'settings-privacy', 'settings-learning'])
		expect(sections.map((s) => s.get('h3').text())).toEqual(['Notifications', 'Login confirmation', 'Data and privacy', 'Learning mode and other settings'])
		for (const section of sections) {
			expect(section.attributes('aria-labelledby')).toBe(section.get('h3').attributes('id'))
		}
	})
})
