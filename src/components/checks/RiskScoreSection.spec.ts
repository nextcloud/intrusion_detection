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
}))

const mounted: { unmount: () => void }[] = []

/**
 * @param name - The setting
 * @param value - Its value
 * @param overrides - Further fields
 */
function setting(name: string, value: number | boolean | string[], overrides: Partial<GlobalSetting> = {}): GlobalSetting {
	const type = typeof value === 'boolean' ? 'bool' : Array.isArray(value) ? 'string_list' : 'int'
	return { name, type, default: value, min: null, max: null, choices: [], value, label: name, help: '', unit: '', group: 'risk', ...overrides }
}

beforeEach(() => {
	state.settings = [
		setting('risk_enabled', true, { label: 'Use the risk score' }),
		setting('risky_network_office_networks', ['203.0.113.0/24'], { type: 'cidr_list', group: 'risky_network', label: 'Office networks' }),
		setting('risky_network_exempt_groups', [], { group: 'risky_network', label: 'Exempt groups' }),
	]
	state.templates = {
		riskPoints: 'Points: 2 for an attack tool, and -10 for an office network.',
		riskTiers: 'From 2 points, the limits are multiplied by 0.5. From 4 points, by 0.25.',
	}
})

describe('RiskScoreSection', () => {
	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(updateSettings).mockReset()
		document.body.innerHTML = ''
	})

	test('shows the switch and the fixed points and tiers as text', () => {
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		expect(wrapper.get('[data-test="risk-points"]').text()).toBe('Points: 2 for an attack tool, and -10 for an office network.')
		expect(wrapper.get('[data-test="risk-tiers"]').text()).toContain('From 4 points, by 0.25.')
		expect(wrapper.text()).toContain('Use the risk score')
		expect(wrapper.findAll('input[type="text"]')).toHaveLength(0)
		expect(wrapper.text()).toContain('On')
	})

	test('saves the switch', async () => {
		vi.mocked(updateSettings).mockResolvedValue({ settings: state.settings, templates: state.templates })
		const wrapper = mount(RiskScoreSection, { attachTo: document.body })
		mounted.push(wrapper)
		await wrapper.get('input[type="checkbox"]').setValue(false)
		await wrapper.get('form').trigger('submit')
		await flushPromises()
		expect(updateSettings).toHaveBeenCalledWith({ risk_enabled: false })
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
		expect(wrapper.get('a[href="#blocks-lists"]').text()).toContain('Choose the network lists on the Blocks tab')
	})
})
