/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h, nextTick } from 'vue'
import AdminSettings from './AdminSettings.vue'
import { state } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

describe('the admin page', () => {
	beforeEach(() => {
		Element.prototype.scrollIntoView = vi.fn()
		state.status = makeStatus()
		window.history.replaceState(null, '', '#overview')
	})

	afterEach(() => {
		state.status = null
		document.body.innerHTML = ''
	})

	const mountPage = () => mount(AdminSettings, {
		attachTo: document.body,
		global: { stubs: { KeepAlive: defineComponent({ setup: (_, { slots }) => () => slots.default?.() }), TabContent: defineComponent({ render: () => h('div') }), StatusBanner: defineComponent({ render: () => h('div', { 'data-test': 'banner' }) }) } },
	})

	test('shows the tabs right under the header, before the status', () => {
		const wrapper = mountPage()
		const order = wrapper.findAll('header, [role="tablist"], [data-test="banner"]').map((el) => el.element.tagName === 'HEADER' ? 'header' : (el.attributes('role') ?? 'banner'))
		expect(order).toEqual(['header', 'tablist', 'banner'])
	})

	test('shows the full banner on the Overview and the one-line strip elsewhere', async () => {
		const wrapper = mountPage()
		expect(wrapper.find('[data-test="banner"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="status-strip"]').exists()).toBe(false)

		await wrapper.find('[data-tab="checks"]').trigger('click')
		expect(wrapper.find('[data-test="banner"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="status-strip"]').exists()).toBe(true)

		await wrapper.find('[data-test="status-strip"] button').trigger('click')
		await nextTick()
		expect(wrapper.find('[aria-selected="true"]').attributes('data-tab')).toBe('overview')
		expect(wrapper.find('[data-test="banner"]').exists()).toBe(true)
	})
})
