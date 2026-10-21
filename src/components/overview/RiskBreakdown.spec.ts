/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Risk } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import DetectionNarrative from './DetectionNarrative.vue'
import RiskBreakdown from './RiskBreakdown.vue'
import { makeDetail } from '../../tests/fixtures.ts'

/**
 * @param overrides - Fields to change
 */
function makeRisk(overrides: Partial<Risk> = {}): Risk {
	return {
		score: 3,
		tier: 'elevated',
		tierLabel: 'Elevated',
		tierElevated: 2,
		tierHigh: 4,
		parts: [
			{ fact: 'hosting', label: 'cloud hosting network', points: 1 },
			{ fact: 'attack_tool', label: 'attack tool "python-requests"', points: 2 },
		],
		lowered: [{ param: 'min_failures', label: 'Failures', plain: 10, effective: 5 }],
		...overrides,
	}
}

describe('RiskBreakdown', () => {
	test('shows the score, its tier and every part with its points', () => {
		const wrapper = mount(RiskBreakdown, { props: { risk: makeRisk() } })
		expect(wrapper.text()).toContain('Risk score of the address')
		expect(wrapper.text()).toContain('3')
		expect(wrapper.text()).toContain('Elevated')
		const parts = wrapper.findAll('li')
		expect(parts[0]!.text()).toContain('cloud hosting network')
		expect(parts[0]!.text()).toContain('+1')
		expect(parts[1]!.text()).toContain('attack tool "python-requests"')
		expect(parts[1]!.text()).toContain('+2')
	})

	test('says which limits were lower because of the score', () => {
		const wrapper = mount(RiskBreakdown, { props: { risk: makeRisk() } })
		expect(wrapper.text()).toContain('lower limits applied to this address')
		expect(wrapper.text()).toMatch(/Failures:\s*5\s*instead of 10/)
	})

	test('negative points, such as an office network, have their sign', () => {
		const wrapper = mount(RiskBreakdown, {
			props: { risk: makeRisk({ score: -10, tier: 'normal', tierLabel: 'Normal', parts: [{ fact: 'office', label: 'office network 203.0.113.0/24', points: -10 }], lowered: [] }) },
		})
		expect(wrapper.text()).toContain('-10')
		expect(wrapper.text()).not.toContain('lower limits')
	})

	test('a score without parts says nothing was known', () => {
		const wrapper = mount(RiskBreakdown, { props: { risk: makeRisk({ score: 0, tier: 'normal', tierLabel: 'Normal', parts: [], lowered: [] }) } })
		expect(wrapper.text()).toContain('Nothing suspicious was known about this address.')
	})

	test('the scale has a text equivalent', () => {
		const wrapper = mount(RiskBreakdown, { props: { risk: makeRisk() } })
		expect(wrapper.get('[role="img"]').attributes('aria-label')).toBe('Score 3; elevated from 2, high from 4')
	})

	test('labels from the server are shown as text, never as markup', () => {
		const wrapper = mount(RiskBreakdown, { props: { risk: makeRisk({ parts: [{ fact: 'attack_tool', label: 'attack tool "<img src=x onerror=alert(1)>"', points: 2 }] }) } })
		expect(wrapper.find('img').exists()).toBe(false)
		expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>')
	})

	test('the detection detail shows the breakdown only when the detection has a score', () => {
		expect(mount(DetectionNarrative, { props: { detail: makeDetail() } }).find('[data-test="risk-breakdown"]').exists()).toBe(false)
		const withRisk = mount(DetectionNarrative, { props: { detail: makeDetail({ risk: makeRisk() }) } })
		expect(withRisk.find('[data-test="risk-breakdown"]').exists()).toBe(true)
	})
})
