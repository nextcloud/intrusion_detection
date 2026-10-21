/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import TimeStamp from './TimeStamp.vue'

describe('a time in the interface', () => {
	test('is relative, with the absolute date and time on hover', () => {
		const at = Math.floor(Date.now() / 1000) - 5 * 60
		const wrapper = mount(TimeStamp, { props: { timestamp: at } })
		expect(wrapper.text()).toMatch(/5 minutes ago/)
		expect(wrapper.attributes('title')).toContain(String(new Date(at * 1000).getFullYear()))
	})

	test('is shorter in dense rows', () => {
		const wrapper = mount(TimeStamp, { props: { timestamp: Math.floor(Date.now() / 1000) - 5 * 60, short: true } })
		expect(wrapper.text()).toMatch(/5 min\. ago/)
	})
})
