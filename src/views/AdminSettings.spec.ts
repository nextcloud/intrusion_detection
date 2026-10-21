/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h, inject } from 'vue'
import AdminSettings from './AdminSettings.vue'
import { state } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

const OpenCheck = defineComponent({
	setup() {
		const openCheck = inject<{ value: string | null }>('ids-open-check')
		return () => h('div', { 'data-test': 'open-check' }, openCheck?.value ?? '')
	},
})

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
		global: { stubs: { KeepAlive: defineComponent({ setup: (_, { slots }) => () => slots.default?.() }), TabContent: OpenCheck } },
	})

	const tabIds = (wrapper: ReturnType<typeof mountPage>) => wrapper.findAll('[role="tab"]').map((tab) => tab.attributes('data-tab'))
	const activeTab = (wrapper: ReturnType<typeof mountPage>) => wrapper.find('[aria-selected="true"]').attributes('data-tab')

	/**
	 * @param hash - The new location hash
	 */
	async function navigate(hash: string) {
		window.history.replaceState(null, '', hash)
		window.dispatchEvent(new HashChangeEvent('hashchange'))
		await flushPromises()
	}

	test('the header has the status sentence and no switch for advanced options', () => {
		const wrapper = mountPage()
		const header = wrapper.get('header')
		expect(header.find('[data-test="status-strip"]').exists()).toBe(true)
		expect(header.find('input[type="checkbox"]').exists()).toBe(false)
		// The state is said once: in the header, not again above every tab.
		expect(wrapper.findAll('[data-test="status-strip"]')).toHaveLength(1)
	})

	test('the header has no documentation link', () => {
		state.docUrl = 'https://docs.example.org/admin-intrusion-detection'
		try {
			const wrapper = mountPage()
			expect(wrapper.get('header').find(`[href="${state.docUrl}"]`).exists()).toBe(false)
		} finally {
			state.docUrl = ''
		}
	})

	test('the Incidents tab is always in the tab list', () => {
		const wrapper = mountPage()
		expect(tabIds(wrapper)).toEqual(['overview', 'protection', 'blocks', 'settings', 'incidents'])
	})

	test('a link to the Incidents tab opens it', async () => {
		const wrapper = mountPage()
		await navigate('#incidents')
		expect(activeTab(wrapper)).toBe('incidents')
	})

	test('links of the former tabs land on the new ones', async () => {
		const wrapper = mountPage()
		await navigate('#checks/credential_stuffing')
		expect(activeTab(wrapper)).toBe('protection')
		expect(wrapper.get('[data-test="open-check"]').text()).toBe('credential_stuffing')

		await navigate('#notifications')
		expect(activeTab(wrapper)).toBe('settings')
		await navigate('#decoys')
		expect(activeTab(wrapper)).toBe('blocks')
		await navigate('#advanced')
		expect(activeTab(wrapper)).toBe('settings')
		await navigate('#accounts')
		expect(activeTab(wrapper)).toBe('settings')
	})

	test('a link to a section scrolls to it', async () => {
		const section = document.createElement('div')
		section.id = 'settings-privacy'
		document.body.appendChild(section)
		mountPage()
		await navigate('#settings-privacy')
		expect(section.scrollIntoView).toHaveBeenCalled()
	})

	test('"things need attention" leads to the list on the overview', async () => {
		const wrapper = mountPage()
		await navigate('#protection')
		const list = document.createElement('div')
		list.id = 'overview-attention'
		document.body.appendChild(list)
		await wrapper.get('[data-test="status-strip"] button').trigger('click')
		await flushPromises()
		expect(activeTab(wrapper)).toBe('overview')
		expect(list.scrollIntoView).toHaveBeenCalled()
	})
})
