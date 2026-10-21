/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection } from '../types.ts'

import { describe, expect, test } from 'vitest'
import { makeDetail } from '../tests/fixtures.ts'
import { incidentSubjects, requestKey, subjectKey } from './incidents.ts'

/**
 * @param overrides - Fields to change
 */
function detection(overrides: Partial<Detection>): Detection {
	return { ...makeDetail().detection, ...overrides }
}

describe('the subjects of the Incidents tab', () => {
	test('one entry per address, or per account for detections without an address, newest first', () => {
		const subjects = incidentSubjects([
			detection({ id: 1, ip: '203.0.113.7', uid: 'alice', checkName: 'Credential stuffing', severity: 'medium', enforced: false, outcome: 'observed', lastSeenAt: 100 }),
			detection({ id: 2, ip: '203.0.113.7', uid: null, checkName: 'Trap URLs', severity: 'high', enforced: true, outcome: 'acted', lastSeenAt: 300 }),
			detection({ id: 3, ip: '203.0.113.7', uid: null, checkName: 'Credential stuffing', severity: 'low', enforced: false, outcome: 'observed', lastSeenAt: 200 }),
			detection({ id: 4, ip: null, uid: 'bob', checkName: 'Admin change alerts', severity: 'low', enforced: false, outcome: 'observed', lastSeenAt: 400 }),
			detection({ id: 5, ip: null, uid: null, checkName: 'Admin change alerts', lastSeenAt: 500 }),
		])
		expect(subjects).toEqual([
			{ key: 'user:bob', type: 'user', value: 'bob', severity: 'low', outcome: 'observed', checks: ['Admin change alerts'], detections: 1, updatedAt: 400 },
			{ key: 'address:203.0.113.7', type: 'address', value: '203.0.113.7', severity: 'high', outcome: 'acted', checks: ['Trap URLs', 'Credential stuffing'], detections: 3, updatedAt: 300 },
		])
	})

	test('a subject says the most Nextcloud did, never "Acted on" when it only notified or recorded', () => {
		const outcome = (...outcomes: Detection['outcome'][]) => incidentSubjects(outcomes.map((o, i) => detection({ id: i, ip: '203.0.113.7', outcome: o })))[0]!.outcome
		expect(outcome('recorded', 'notified', 'observed')).toBe('notified')
		expect(outcome('observed', 'recorded')).toBe('recorded')
		expect(outcome('observed')).toBe('observed')
		expect(outcome('notified', 'acted')).toBe('acted')
	})

	test('requests about the same subject and period have the same key', () => {
		expect(requestKey({ type: 'address', value: '203.0.113.7', since: null, until: null })).toBe(requestKey({ type: 'address', value: '203.0.113.7', since: null, until: null }))
		expect(requestKey({ type: 'address', value: '203.0.113.7', since: 1, until: 2 })).not.toBe(requestKey({ type: 'address', value: '203.0.113.7', since: null, until: null }))
		expect(requestKey({ type: 'user', value: 'alice', since: 1, until: 2 })).not.toBe(requestKey({ type: 'user', value: 'alice', since: 1, until: 3 }))
	})

	test('keys tell accounts and addresses apart', () => {
		expect(subjectKey('user', 'alice')).not.toBe(subjectKey('address', 'alice'))
		expect(incidentSubjects([])).toEqual([])
	})
})
