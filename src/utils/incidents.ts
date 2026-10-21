/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection, IncidentSubjectType, Severity } from '../types.ts'

import { highestSeverity } from './groups.ts'

/** An address or account that recent detections are about, listed on the Incidents tab */
export interface IncidentSubject {
	key: string
	type: IncidentSubjectType
	value: string
	severity: Severity
	/** Whether Nextcloud acted on at least one of its detections */
	enforced: boolean
	/** The check names, most recent first, without repeats */
	checks: string[]
	detections: number
	updatedAt: number
}

/**
 * @param type - Account or address
 * @param value - The account or the address
 */
export function subjectKey(type: IncidentSubjectType, value: string): string {
	return type + ':' + value
}

/**
 * Fold detections into one entry per subject: the address a detection came
 * from, or the account it is about when it has no address. Detections about
 * neither, such as a changed setting, are left out. The most recently
 * updated subject comes first.
 *
 * @param detections - The detections, in any order
 */
export function incidentSubjects(detections: Detection[]): IncidentSubject[] {
	const groups = new Map<string, { type: IncidentSubjectType, value: string, detections: Detection[] }>()
	for (const detection of detections) {
		const type: IncidentSubjectType | null = detection.ip ? 'address' : (detection.uid ? 'user' : null)
		if (type === null) {
			continue
		}
		const value = (type === 'address' ? detection.ip : detection.uid)!
		const key = subjectKey(type, value)
		const group = groups.get(key) ?? { type, value, detections: [] }
		group.detections.push(detection)
		groups.set(key, group)
	}
	return [...groups.entries()]
		.map(([key, group]) => {
			const sorted = [...group.detections].sort((a, b) => b.lastSeenAt - a.lastSeenAt)
			return {
				key,
				type: group.type,
				value: group.value,
				severity: highestSeverity(sorted),
				enforced: sorted.some((d) => d.enforced),
				checks: [...new Set(sorted.map((d) => d.checkName))],
				detections: sorted.length,
				updatedAt: sorted[0]!.lastSeenAt,
			}
		})
		.sort((a, b) => b.updatedAt - a.updatedAt)
}
