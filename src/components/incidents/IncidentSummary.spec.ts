/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { IncidentSummary as Summary } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import IncidentSummary from './IncidentSummary.vue'

/**
 * @param counts - The counts of the summary
 */
function summary(counts: Summary['counts']): Summary {
	return {
		headline: 'Nextcloud recorded events.',
		happened: [],
		startedAt: null,
		foundAt: null,
		lastActivityAt: null,
		affected: [],
		dataCategories: [],
		dataNote: null,
		measures: [],
		openItems: [],
		counts,
	}
}

describe('the summary of an incident report', () => {
	test('counts events and detections with a noun and the right plural', () => {
		const many = mount(IncidentSummary, { props: { summary: summary({ entries: 3, detections: 3, enforced: 2, observed: 0 }) } })
		expect(many.get('[data-test="incident-counts"]').text()).toBe('3 events · 2 detections acted on · 0 detections only observed')
		const one = mount(IncidentSummary, { props: { summary: summary({ entries: 1, detections: 2, enforced: 1, observed: 1 }) } })
		expect(one.get('[data-test="incident-counts"]').text()).toBe('1 event · 1 detection acted on · 1 detection only observed')
	})
})
