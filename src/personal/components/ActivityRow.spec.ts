/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ActivityItem } from '../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import ActivityRow from './ActivityRow.vue'
import { activityItem, login } from '../../tests/personalFixtures.ts'

const item: ActivityItem = {
	id: 'change-1',
	kind: 'change',
	at: 1_792_580_400,
	day: '2026-10-20',
	login: null,
	change: { id: 1, type: 'password', label: 'Password changed', oldValue: null, newValue: null, changedBy: 'admin', address: '203.0.113.66', createdAt: 1_792_580_400, detectionId: null } as unknown as ActivityItem['change'],
	failedLogins: null,
	event: null,
}

describe('a row of the activity timeline', () => {
	test('the time and each part of the meta line wrap on their own, never inside a word', () => {
		const wrapper = mount(ActivityRow, { props: { item } })
		const meta = wrapper.get('p:nth-of-type(2)')
		const parts = meta.element.children
		expect(parts.length).toBeGreaterThan(1)
		expect(parts[0]!.tagName).toBe('TIME')
		// Every part is its own element, so the line can break between them.
		expect([...parts].every((part) => part.textContent!.trim() !== '')).toBe(true)
	})

	test('a login shows its labels next to its title, and its address stays in the details', () => {
		const wrapper = mount(ActivityRow, { props: { item: activityItem({ login: login(3, { labels: ['new_network', 'new_device'] }) }) } })
		const title = wrapper.get('p:nth-of-type(1)')
		expect(title.get('[data-test="label-new_network"]').text()).toBe('New network')
		expect(title.get('[data-test="label-new_device"]').text()).toBe('New device')
		expect(wrapper.get('p:nth-of-type(2)').text()).toContain('198.51.100.3')
	})

	test('a login without labels shows none', () => {
		const wrapper = mount(ActivityRow, { props: { item: activityItem({ login: login(3) }) } })
		expect(wrapper.find('[data-test^="label-"]').exists()).toBe(false)
	})
})
