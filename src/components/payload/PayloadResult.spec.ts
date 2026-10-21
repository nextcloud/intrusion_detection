/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { PayloadTest } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import PayloadResult from './PayloadResult.vue'

/**
 * A test result as the API returns it.
 *
 * @param overrides - Fields to change
 */
function result(overrides: Partial<PayloadTest> = {}): PayloadTest {
	return {
		kind: 'url',
		prefilter: true,
		pathExcluded: false,
		minWeight: 3,
		maxBytes: 8192,
		signaturesVersion: 1,
		fires: true,
		modes: { anonymous: 'protect', authenticated: 'observe' },
		values: [
			{
				location: 'query',
				name: 'data',
				skipped: null,
				truncated: false,
				normalised: 'jybpuianmsc9jze=',
				decoded: ["' OR '1'='1"],
				forms: [
					{ encoding: 'none', text: 'jybpuianmsc9jze=', weight: 0, matches: [] },
					{ encoding: 'base64', text: "' or '1'='1", weight: 3, matches: [{ id: 'sql_tautology', weight: 3, description: 'A quote followed by a comparison that is always true' }] },
				],
				weight: 3,
				fires: true,
			},
			{ location: 'query', name: 'password', skipped: 'secret', truncated: false },
		],
		...overrides,
	}
}

describe('PayloadResult', () => {
	test('a hit shows every step: normalised, decoded, the signatures and their weights', () => {
		const wrapper = mount(PayloadResult, { props: { result: result() } })
		expect(wrapper.get('[data-test="payload-verdict"]').text()).toBe('Would fire')
		expect(wrapper.text()).toContain('The strongest value reaches a weight of 3; 3 is needed.')
		expect(wrapper.text()).toContain('Visitors who are not logged in: blocked. Logged-in users: recorded only.')
		expect(wrapper.get('[data-test="payload-normalised"]').text()).toBe('jybpuianmsc9jze=')
		expect(wrapper.get('[data-test="payload-decoded"]').text()).toBe("' OR '1'='1")
		const match = wrapper.get('[data-test="payload-match"]')
		expect(match.text()).toContain('+3')
		expect(match.text()).toContain('sql_tautology')
		expect(wrapper.text()).toContain('After decoding base64')
		expect(wrapper.text()).toContain('weight 3 / 3')
	})

	test('fields that are never inspected say why, and show no value', () => {
		const wrapper = mount(PayloadResult, { props: { result: result() } })
		expect(wrapper.text()).toContain('password')
		expect(wrapper.text()).toContain('Never inspected: a password, secret or token field can contain anything.')
	})

	test('a harmless address stops after the quick scan', () => {
		const wrapper = mount(PayloadResult, { props: { result: result({ fires: false, prefilter: false, values: [] }) } })
		expect(wrapper.get('[data-test="payload-verdict"]').text()).toBe('Would not fire')
		expect(wrapper.text()).toContain('stops after its quick first scan')
	})

	test('a file name in WebDAV is never inspected', () => {
		const wrapper = mount(PayloadResult, { props: { result: result({ fires: false, pathExcluded: true, values: [] }) } })
		expect(wrapper.text()).toContain('File names are never inspected')
	})

	test('a value below the threshold says how far it got', () => {
		const below = result({ fires: false })
		below.values[0]!.weight = 1
		below.values[0]!.fires = false
		const wrapper = mount(PayloadResult, { props: { result: below } })
		expect(wrapper.text()).toContain('reaches a weight of 1; 3 is needed')
	})
})
