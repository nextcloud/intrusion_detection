/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import RiskScoreSection from './RiskScoreSection.vue'
import RiskyNetworkSection from './RiskyNetworkSection.vue'
import { updateSettings } from '../../services/api.ts'
import { state } from '../../store.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateSettings: vi.fn(),
	fetchChecks: vi.fn(() => new Promise(() => {})),
}))

const mounted: { unmount: () => void }[] = []

/**
 * @param name - The setting
 * @param value - Its value
 * @param overrides - Further fields
 */
function setting(name: string, value: number | boolean | string[], overrides: Partial<GlobalSetting> = {}): GlobalSetting {
	const type = typeof value === 'boolean' ? 'bool' : Array.isArray(value) ? 'string_list' : (name.startsWith('risk_factor') ? 'float' : 'int')
	return { name, type, default: value, min: null, max: null, choices: [], value, label: name, help: '', unit: '', group: 'risk', ...overrides }
}

beforeEach(() => {
	state.settings = [
		setting('risk_enabled', true, { label: 'Use the risk score' }),
		setting('risk_points_attack_tool', 2, { label: 'Attack tool', help: 'A failed login with an attack tool.' }),
		setting('risk_points_tor', 2, { label: 'Tor exit node' }),
		setting('risk_points_hosting', 1, { label: 'Cloud hosting network' }),
		setting('risk_points_office', -10, { label: 'Office network' }),
		setting('risk_tier_elevated', 2),
		setting('risk_tier_high', 4),
		setting('risk_factor_elevated', 0.5),
		setting('risk_factor_high', 0.25),
		setting('risky_network_office_networks', ['203.0.113.0/24'], { type: 'cidr_list', group: 'risky_network', label: 'Office networks' }),
		setting('risky_network_exempt_groups', [], { group: 'risky_network', label: 'Exempt groups' }),
	]
	state.templates = {
		riskNormal: 'Below {risk_tier_elevated} points: the limits as configured.',
		riskElevated: 'From {risk_tier_elevated} points: limits × {risk_factor_elevated}, never below 2.',
		riskHigh: 'From {risk_tier_high} points: limits × {risk_factor_high}, and every password login needs extra confirmation.',
	}
})

describe('RiskScoreSection', () => {
	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(updateSettings).mockReset()
		document.body.innerHTML = ''
	})

	test('shows the point table with the current points', () => {
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		const rows = wrapper.findAll('tbody tr')
		expect(rows.map((row) => row.find('th').text())).toEqual([
			expect.stringContaining('Attack tool'),
			expect.stringContaining('Tor exit node'),
			expect.stringContaining('Cloud hosting network'),
			expect.stringContaining('Office network'),
		])
		expect(rows[0]!.find('td').text()).toBe('2')
		expect(rows[3]!.find('td').text()).toBe('-10')
		expect(wrapper.text()).toContain('On')
	})

	test('the tiers are live sentences that follow the fields while typing', async () => {
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		expect(wrapper.text()).toContain('From 4 points: limits × 0.25')
		// The four points come first, then the two tiers.
		await wrapper.findAll('input[type="text"]')[5]!.setValue('6')
		await flushPromises()
		expect(wrapper.text()).toContain('From 6 points: limits × 0.25')
	})

	test('says when the score is off', () => {
		state.settings = state.settings.map((s) => (s.name === 'risk_enabled' ? { ...s, value: false } : s))
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		expect(wrapper.text()).toContain('Off')
	})

	test('is not shown without its settings', () => {
		state.settings = []
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		expect(wrapper.find('[data-test="risk-score"]').exists()).toBe(false)
	})
})

describe('RiskyNetworkSection', () => {
	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		document.body.innerHTML = ''
	})

	test('edits the office networks and exempt groups, and links to the network lists', () => {
		const wrapper = mount(RiskyNetworkSection, { props: { check: makeCheck({ id: 'risky_network', params: [] }) }, attachTo: document.body })
		mounted.push(wrapper)
		expect(wrapper.text()).toContain('Office networks')
		expect(wrapper.text()).toContain('Exempt groups')
		expect(wrapper.text()).not.toContain('Use the risk score')
		expect(wrapper.get('a[href="#blocks/blocklists"]').text()).toContain('Choose the network lists on the Blocks tab')
	})
})
