/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection, Severity } from '../types.ts'

import { APP_ID } from './format.ts'
import { n, t } from './l10n.ts'

export type DetectionEntry
	= { type: 'single', key: string, detection: Detection }
		| { type: 'group', key: string, detections: Detection[] }

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']

/**
 * Detections that read the same in the list: same check, address, account
 * and outcome.
 *
 * @param detection - A detection
 */
function sameKey(detection: Detection): string {
	return [detection.checkId, detection.ip ?? '', detection.uid ?? '', detection.enforced ? '1' : '0'].join('|')
}

/**
 * Fold runs of detections that read the same into one entry, e.g.
 * "17 × Admin change alerts", keeping the order of the list.
 *
 * @param detections - The list, newest first
 */
export function groupDetections(detections: Detection[]): DetectionEntry[] {
	const entries: DetectionEntry[] = []
	let run: Detection[] = []
	const flush = () => {
		if (run.length === 1) {
			entries.push({ type: 'single', key: `d${run[0]!.id}`, detection: run[0]! })
		} else if (run.length > 1) {
			entries.push({ type: 'group', key: `g${run[0]!.id}`, detections: run })
		}
		run = []
	}
	for (const detection of detections) {
		if (run.length > 0 && sameKey(run[0]!) !== sameKey(detection)) {
			flush()
		}
		run.push(detection)
	}
	flush()
	return entries
}

/**
 * The highest severity in a group.
 *
 * @param detections - The group
 */
export function highestSeverity(detections: Detection[]): Severity {
	return detections.reduce<Severity>((highest, d) => SEVERITIES.indexOf(d.severity) > SEVERITIES.indexOf(highest) ? d.severity : highest, 'low')
}

/**
 * How long a group took, roughly: "within 7 minutes".
 *
 * @param detections - The group
 */
export function groupSpan(detections: Detection[]): string {
	const first = Math.min(...detections.map((d) => d.createdAt))
	const last = Math.max(...detections.map((d) => d.lastSeenAt))
	const seconds = Math.max(0, last - first)
	if (seconds < 60) {
		return t(APP_ID, 'within a minute')
	}
	if (seconds < 3600) {
		return n(APP_ID, 'within %n minute', 'within %n minutes', Math.ceil(seconds / 60))
	}
	if (seconds < 86400) {
		return n(APP_ID, 'within %n hour', 'within %n hours', Math.ceil(seconds / 3600))
	}
	return n(APP_ID, 'within %n day', 'within %n days', Math.ceil(seconds / 86400))
}

/**
 * The summary all detections of a group share, or null.
 *
 * @param detections - The group
 */
export function commonSummary(detections: Detection[]): string | null {
	const first = detections[0]?.summary ?? null
	return first !== null && detections.every((d) => d.summary === first) ? first : null
}
