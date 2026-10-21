/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import { h } from 'vue'
import ShowMore from './ShowMore.vue'

function mountToggle(props: Record<string, unknown> = {}) {
	return mount(ShowMore, {
		props: { label: 'Show the example payload', ...props },
		slots: { default: () => h('pre', { 'data-test': 'content' }, '{ }') },
	})
}

describe('a reference section behind a toggle', () => {
	test('starts closed and renders nothing of its content', () => {
		const wrapper = mountToggle({ note: '3 kinds of data' })
		const button = wrapper.get('button')
		expect(button.text()).toContain('Show the example payload')
		expect(button.text()).toContain('3 kinds of data')
		expect(button.attributes('aria-expanded')).toBe('false')
		expect(wrapper.find('[data-test="content"]').exists()).toBe(false)
		const region = wrapper.get(`#${button.attributes('aria-controls')}`)
		expect(region.attributes('inert')).toBeDefined()
	})

	test('opens and closes with its button', async () => {
		const wrapper = mountToggle()
		const button = wrapper.get('button')
		await button.trigger('click')
		expect(button.attributes('aria-expanded')).toBe('true')
		expect(wrapper.find('[data-test="content"]').exists()).toBe(true)
		expect(wrapper.emitted('update:open')).toEqual([[true]])
		await button.trigger('click')
		expect(wrapper.find('[data-test="content"]').exists()).toBe(false)
	})

	test('can be opened from outside', () => {
		const wrapper = mountToggle({ open: true })
		expect(wrapper.find('[data-test="content"]').exists()).toBe(true)
	})
})
