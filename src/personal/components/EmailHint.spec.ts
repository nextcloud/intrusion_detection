/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test } from 'vitest'
import EmailHint from './EmailHint.vue'
import { overview } from '../../tests/personalFixtures.ts'
import { personal } from '../store.ts'

enableAutoUnmount(afterEach)

describe('EmailHint', () => {
	test('is not shown to accounts with an email address or a second factor', () => {
		personal.overview = overview({ emailHint: null })
		expect(mount(EmailHint).find('[data-test="email-hint"]').exists()).toBe(false)
	})

	test('says why in the words of the concept and offers both ways', () => {
		personal.overview = overview({ emailHint: { emailUrl: '/settings/user/profile-contact', secondFactorUrl: '/settings/user/security#two-factor-auth' } })
		const wrapper = mount(EmailHint)
		expect(wrapper.text()).toContain('If Nextcloud notices something suspicious, it can only confirm it\'s you with an email address or a second factor. Without either, some logins may be refused.')
		expect(wrapper.get('[data-test="add-email"]').attributes('href')).toBe('/settings/user/profile-contact')
		expect(wrapper.get('[data-test="add-email"]').text()).toBe('Add email address')
		expect(wrapper.get('[data-test="set-up-second-factor"]').attributes('href')).toBe('/settings/user/security#two-factor-auth')
		expect(wrapper.get('[data-test="set-up-second-factor"]').text()).toBe('Set up two-factor authentication')
	})

	test('offers no second factor when none can be set up', () => {
		personal.overview = overview({ emailHint: { emailUrl: '/settings/user/profile-contact', secondFactorUrl: null } })
		const wrapper = mount(EmailHint)
		expect(wrapper.find('[data-test="add-email"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="set-up-second-factor"]').exists()).toBe(false)
	})
})
