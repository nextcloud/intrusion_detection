/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ActivityItem } from '../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import ActivityRow from './ActivityRow.vue'

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
})
