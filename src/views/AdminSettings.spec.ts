/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { TabDefinition } from '../extensions.ts'

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent } from 'vue'
import AdminSettings from './AdminSettings.vue'
import { fetchWaitingLogins } from '../services/api.ts'
import { state, waitingLogins } from '../store.ts'
import { makeStatus } from '../tests/fixtures.ts'

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchWaitingLogins: vi.fn(() => Promise.resolve([])),
}))

// Every tab shows which check a link opened.
vi.mock('../extensions.ts', async (importOriginal) => {
	const original = await importOriginal<{ tabs: TabDefinition[] }>()
	const { defineComponent, h, inject } = await import('vue')
	const OpenCheck = defineComponent({
		setup() {
			const openCheck = inject<{ value: string | null }>('ids-open-check')
			return () => h('div', { 'data-test': 'open-check' }, openCheck?.value ?? '')
		},
	})
	return { ...original, tabs: original.tabs.map((tab) => ({ ...tab, component: OpenCheck })) }
})

enableAutoUnmount(afterEach)

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
		global: { stubs: { KeepAlive: defineComponent({ setup: (_, { slots }) => () => slots.default?.() }) } },
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

	test('the header has the status sentence and, next to it, the master switch; no switch for advanced options', () => {
		const wrapper = mountPage()
		const header = wrapper.get('header')
		expect(header.find('[data-test="status-strip"]').exists()).toBe(true)
		const switches = header.findAll('input[type="checkbox"]')
		expect(switches).toHaveLength(1)
		expect(header.get('[data-test="master-switch"]').text()).toBe('Intrusion detection is on')
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

	test('looks for waiting logins and counts them in the header', async () => {
		state.status = makeStatus({ problems: [] })
		vi.mocked(fetchWaitingLogins).mockResolvedValue([{ id: 7, uid: 'alice', displayName: 'Alice', ip: null, createdAt: 1, expiresAt: 2, canDecide: true }])
		const wrapper = mountPage()
		await flushPromises()
		expect(fetchWaitingLogins).toHaveBeenCalled()
		expect(wrapper.get('[data-test="status-strip"] button').text()).toBe('1 thing needs attention')
		waitingLogins.value = []
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

	test('a section that is still missing is no longer looked for once the page is gone', async () => {
		vi.useFakeTimers()
		try {
			const wrapper = mountPage()
			window.history.replaceState(null, '', '#settings-privacy')
			window.dispatchEvent(new HashChangeEvent('hashchange'))
			await vi.advanceTimersByTimeAsync(250)
			wrapper.unmount()
			const lookups = vi.spyOn(document, 'getElementById')
			await vi.advanceTimersByTimeAsync(3000)
			expect(lookups).not.toHaveBeenCalledWith('settings-privacy')
		} finally {
			vi.useRealTimers()
		}
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
