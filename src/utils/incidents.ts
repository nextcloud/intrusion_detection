/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection, DetectionOutcome, IncidentRequest, IncidentSubjectType, Severity } from '../types.ts'

import { highestSeverity } from './groups.ts'

/** An address or account that recent detections are about, listed on the Incidents tab */
export interface IncidentSubject {
	key: string
	type: IncidentSubjectType
	value: string
	severity: Severity
	/** The most Nextcloud did about one of its detections */
	outcome: DetectionOutcome
	/** The check names, most recent first, without repeats */
	checks: string[]
	detections: number
	updatedAt: number
}

/** Outcomes from the most to the least that Nextcloud did */
const OUTCOMES: DetectionOutcome[] = ['acted', 'notified', 'recorded', 'observed']

/**
 * The most Nextcloud did about any of the detections.
 *
 * @param detections - At least one detection
 */
export function strongestOutcome(detections: Detection[]): DetectionOutcome {
	return OUTCOMES.find((outcome) => detections.some((d) => d.outcome === outcome)) ?? 'observed'
}

/**
 * @param type - Account or address
 * @param value - The account or the address
 */
export function subjectKey(type: IncidentSubjectType, value: string): string {
	return type + ':' + value
}

/**
 * The same key for requests about the same subject and period.
 *
 * @param request - Subject and period
 */
export function requestKey(request: IncidentRequest): string {
	return [subjectKey(request.type, request.value), request.since ?? '', request.until ?? ''].join('|')
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
				outcome: strongestOutcome(sorted),
				checks: [...new Set(sorted.map((d) => d.checkName))],
				detections: sorted.length,
				updatedAt: sorted[0]!.lastSeenAt,
			}
		})
		.sort((a, b) => b.updatedAt - a.updatedAt)
}
