/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { IncidentEntry as Entry } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import IncidentEntry from './IncidentEntry.vue'

/**
 * @param overrides - Fields to change
 */
function entry(overrides: Partial<Entry> = {}): Entry {
	return {
		id: 'detection:14',
		at: 1_790_000_000,
		endsAt: null,
		lastSeenAt: null,
		kind: 'detection',
		group: 'Trap URLs',
		title: 'Trap URLs',
		severity: 'low',
		enforced: true,
		outcome: 'acted',
		details: ['The address requested a trap.'],
		done: [],
		note: null,
		address: '203.0.113.50',
		accounts: [],
		ref: null,
		...overrides,
	}
}

/**
 * @param props - The entry
 */
function terms(props: Entry): string[] {
	const wrapper = mount(IncidentEntry, { props: { entry: props, kindLabel: 'Detections', expanded: true } })
	return wrapper.findAll('dt').map((term) => term.text())
}

describe('an entry of the incident timeline', () => {
	test('a detection says when it was last seen, not "Until"', () => {
		expect(terms(entry({ lastSeenAt: 1_790_000_600 }))).toEqual(['Last seen', 'Address'])
	})

	test('a block says until when it lasts, and its reference', () => {
		const wrapper = mount(IncidentEntry, { props: { entry: entry({ kind: 'block', endsAt: 1_790_014_400, ref: { type: 'block', id: '2S8X-AXQ6' } }), kindLabel: 'Blocks', expanded: true } })
		expect(wrapper.findAll('dt').map((term) => term.text())).toEqual(['Until', 'Address', 'Reference'])
		expect(wrapper.get('dl > div:last-child code').text()).toBe('2S8X-AXQ6')
	})

	test('a detection says what Nextcloud did, and other entries say nothing about it', () => {
		const badge = (overrides: Partial<Entry>) => mount(IncidentEntry, { props: { entry: entry(overrides), kindLabel: 'Detections' } }).find('[data-test="outcome"]')
		expect(badge({ outcome: 'recorded' }).text()).toBe('Recorded')
		expect(badge({ outcome: 'notified' }).text()).toBe('Notified')
		expect(badge({ kind: 'login', enforced: null, outcome: null }).exists()).toBe(false)
	})

	test('internal ids are not shown', () => {
		const wrapper = mount(IncidentEntry, { props: { entry: entry({ ref: { type: 'detection', id: '14' } }), kindLabel: 'Detections', expanded: true } })
		expect(wrapper.text()).not.toContain('Reference')
		expect(wrapper.text()).not.toContain('detection 14')
	})
})
