/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import StatusStrip from './StatusStrip.vue'
import { makeStatus } from '../tests/fixtures.ts'

describe('the status line of the header', () => {
	test('says the state in one sentence', () => {
		expect(mount(StatusStrip, { props: { status: makeStatus() } }).text()).toContain('Learning until')
		expect(mount(StatusStrip, { props: { status: makeStatus({ state: 'protecting' }) } }).text()).toContain('Protecting this server.')
		expect(mount(StatusStrip, { props: { status: makeStatus({ state: 'off' }) } }).text()).toContain('Off: nothing is checked and nobody is blocked.')
	})

	test('counts the problems that are not mere tips and leads to them', async () => {
		const wrapper = mount(StatusStrip, { props: { status: makeStatus() } })
		const button = wrapper.find('button')
		expect(button.text()).toBe('1 thing needs attention')
		await button.trigger('click')
		expect(wrapper.emitted('attention')).toHaveLength(1)
	})

	test('says nothing more when nothing needs attention', () => {
		const wrapper = mount(StatusStrip, { props: { status: makeStatus({ state: 'protecting', problems: [] }) } })
		expect(wrapper.find('button').exists()).toBe(false)
	})
})
