/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { TabDefinition } from '../extensions.ts'

import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import AdminTabs from './AdminTabs.vue'

const tabs: TabDefinition[] = ['overview', 'checks', 'blocks', 'decoys', 'advanced'].map((id, order) => ({ id, name: () => `Tab ${id}`, icon: '', order }))

/**
 * Pretend the bar is `bar` pixels wide and every tab `tab` pixels.
 *
 * @param bar - The width of the bar
 * @param tab - The width of each tab
 */
function sizes(bar: number, tab: number) {
	vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(bar)
	vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(tab)
}

/**
 * @param active - The active tab
 */
async function mountTabs(active = 'overview') {
	const wrapper = mount(AdminTabs, { props: { tabs, modelValue: active }, attachTo: document.body })
	await nextTick()
	return wrapper
}

const shown = (wrapper: Awaited<ReturnType<typeof mountTabs>>) => wrapper.findAll('[role="tab"]').map((tab) => tab.attributes('data-tab'))

describe('the tab bar', () => {
	afterEach(() => {
		vi.restoreAllMocks()
		document.body.innerHTML = ''
	})

	test('shows every tab when they fit, without a menu', async () => {
		sizes(1000, 150)
		const wrapper = await mountTabs()
		expect(shown(wrapper)).toEqual(['overview', 'checks', 'blocks', 'decoys', 'advanced'])
		expect(wrapper.find('[data-test="more-tabs"]').exists()).toBe(false)
	})

	test('puts the tabs that do not fit into a "More" menu', async () => {
		sizes(500, 150)
		const wrapper = await mountTabs()
		expect(shown(wrapper)).toEqual(['overview', 'checks'])
		expect(wrapper.find('[data-test="more-tabs"]').exists()).toBe(true)
	})

	test('always shows the active tab, even when it would not fit', async () => {
		sizes(500, 150)
		const wrapper = await mountTabs('advanced')
		expect(shown(wrapper)).toEqual(['overview', 'advanced'])
		expect(wrapper.find('[aria-selected="true"]').attributes('data-tab')).toBe('advanced')
		await wrapper.setProps({ modelValue: 'decoys' })
		expect(shown(wrapper)).toEqual(['overview', 'decoys'])
	})

	test('arrow keys reach the tabs in the menu', async () => {
		sizes(500, 150)
		const wrapper = await mountTabs('checks')
		await wrapper.find('[data-tab="checks"]').trigger('keydown', { key: 'ArrowRight' })
		expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual(['blocks'])
		await wrapper.setProps({ modelValue: 'blocks' })
		await nextTick()
		expect(shown(wrapper)).toContain('blocks')
		await wrapper.find('[data-tab="blocks"]').trigger('keydown', { key: 'End' })
		expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual(['advanced'])
	})
})
