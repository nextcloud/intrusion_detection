/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection } from '../types.ts'

import { describe, expect, test } from 'vitest'
import { makeDetail } from '../tests/fixtures.ts'
import { commonSummary, groupDetections, groupSpan, highestSeverity } from './groups.ts'

/**
 * @param id - The id
 * @param overrides - Fields to change
 */
function detection(id: number, overrides: Partial<Detection> = {}): Detection {
	return { ...makeDetail().detection, id: String(id), ...overrides }
}

const adminChange = (id: number, overrides: Partial<Detection> = {}) => detection(id, { checkId: 'admin_change', checkName: 'Admin change alerts', ip: null, uid: null, enforced: false, severity: 'low', ...overrides })

describe('grouping the detection list', () => {
	test('folds a run of detections that read the same into one entry', () => {
		const entries = groupDetections([adminChange(20), adminChange(19), adminChange(18), detection(17), adminChange(16)])
		expect(entries.map((e) => e.type)).toEqual(['group', 'single', 'single'])
		expect(entries[0]!.type === 'group' && entries[0]!.detections.map((d) => d.id)).toEqual(['20', '19', '18'])
	})

	test('keeps detections apart that differ in address, account or outcome', () => {
		const entries = groupDetections([detection(3), detection(2, { ip: '198.51.100.1' }), detection(1, { enforced: false })])
		expect(entries.map((e) => e.type)).toEqual(['single', 'single', 'single'])
	})

	test('a group shows its highest severity, a shared summary, and how long it took', () => {
		const group = [
			adminChange(3, { createdAt: 1000, lastSeenAt: 1400, summary: 'Security setting changed' }),
			adminChange(2, { createdAt: 900, lastSeenAt: 900, severity: 'high', summary: 'Security setting changed' }),
		]
		expect(highestSeverity(group)).toBe('high')
		expect(commonSummary(group)).toBe('Security setting changed')
		expect(commonSummary([group[0]!, { ...group[1]!, summary: 'An app was enabled' }])).toBeNull()
		expect(groupSpan(group)).toBe('within 9 minutes')
		expect(groupSpan([adminChange(1, { createdAt: 0, lastSeenAt: 30 })])).toBe('within a minute')
	})
})
