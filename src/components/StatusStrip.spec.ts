/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import StatusStrip from './StatusStrip.vue'
import { makeStatus } from '../tests/fixtures.ts'

describe('the status strip', () => {
	test('says the state and the figures in one line', () => {
		const wrapper = mount(StatusStrip, { props: { status: makeStatus() } })
		expect(wrapper.text()).toContain('Learning: 7 days left')
		expect(wrapper.text()).toContain('1,234 detections and 2 active blocks in the last 24 hours')
	})

	test('counts the problems that are not mere tips and leads to the overview', async () => {
		const wrapper = mount(StatusStrip, { props: { status: makeStatus() } })
		const button = wrapper.find('button')
		expect(button.text()).toBe('1 thing to look at')
		await button.trigger('click')
		expect(wrapper.emitted('overview')).toHaveLength(1)
	})

	test('offers the overview when nothing needs a look', () => {
		const wrapper = mount(StatusStrip, { props: { status: makeStatus({ state: 'protecting', problems: [] }) } })
		expect(wrapper.text()).toContain('Protecting')
		expect(wrapper.find('button').text()).toBe('Overview')
	})
})
