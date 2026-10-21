/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { ref } from 'vue'
import TabContent from '../components/TabContent.vue'
import ProtectionTab from './ProtectionTab.vue'
import { tabs } from '../extensions.ts'
import { state } from '../store.ts'
import { makeCheck } from '../tests/fixtures.ts'

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchProtectionLevel: vi.fn(() => Promise.resolve({ level: 'recommended' })),
}))

describe('the Protection tab', () => {
	beforeEach(() => {
		Element.prototype.scrollIntoView = vi.fn()
		state.checks = [
			makeCheck({ id: 'credential_stuffing', category: 'login_attacks' }),
			makeCheck({ id: 'trap_url', category: 'traps', texts: { ...makeCheck().texts, name: 'Trap URLs' } }),
		]
		state.settings = []
	})

	afterEach(() => {
		document.body.innerHTML = ''
	})

	test('the protection level on top, then one row per check in its group', () => {
		const wrapper = mount(ProtectionTab, { attachTo: document.body })
		expect(wrapper.find('[data-test="protection-level"]').exists()).toBe(true)
		const groups = wrapper.findAll('[data-test="protection-group"]')
		expect(groups.map((group) => group.get('h3').text())).toEqual(['Logins and passwords', 'Scanning and probing'])
		expect(wrapper.findAll('[data-test="check-row"]')).toHaveLength(2)
		wrapper.unmount()
	})

	test('a link to a check scrolls to its row', async () => {
		const wrapper = mount(ProtectionTab, { attachTo: document.body, global: { provide: { 'ids-open-check': ref('trap_url') } } })
		await flushPromises()
		expect(document.getElementById('check-trap_url')!.scrollIntoView).toHaveBeenCalled()
		wrapper.unmount()
	})

	test('the risk score card is an expert tool, shown below the checks', async () => {
		state.settings = [{ name: 'risk_enabled', type: 'bool', default: true, min: null, max: null, choices: [], value: true, label: 'Risk score', help: '', unit: '', group: 'risk' }]
		const tab = tabs.find((t) => t.id === 'protection')!
		const wrapper = mount(TabContent, { props: { tab: { ...tab, component: ProtectionTab } }, attachTo: document.body })
		await vi.dynamicImportSettled()
		await flushPromises()
		const html = wrapper.html()
		expect(wrapper.find('[data-test="risk-score"]').exists()).toBe(true)
		expect(html.indexOf('data-test="risk-score"')).toBeGreaterThan(html.lastIndexOf('data-test="check-row"'))
		wrapper.unmount()
	})
})
