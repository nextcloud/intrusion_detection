/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Check, DetectionDetail, Status } from '../types.ts'

/**
 * A check as the API presents it, with the texts of concept section 16.3.
 *
 * @param overrides - Fields to change
 */
export function makeCheck(overrides: Partial<Check> = {}): Check {
	return {
		id: 'credential_stuffing',
		category: 'login_attacks',
		internal: false,
		severity: 'medium',
		mode: { configured: 'protect', effective: 'protect', reason: null, missing: null, default: 'protect' },
		texts: {
			name: 'Credential stuffing',
			summary: 'Many different login names failing from one source.',
			detects: 'Attackers buy long lists of usernames and passwords stolen from other websites.',
			decides: 'Fires when one address fails to log in {min_failures} times for at least {min_names} different accounts within {window}.',
			wrong: 'Many people behind one office address mistyping their passwords at the same time.',
			data: 'Failed logins, deleted after 1 hour.',
		},
		decidesTemplate: 'Fires when one address fails to log in {min_failures} times for at least {min_names} different accounts within {window}.',
		decides: 'Fires when one address fails to log in 10 times for at least 5 different accounts within 10 minutes.',
		happens: ['The address is blocked for 4 hours.'],
		responses: [
			{ type: 'ban', label: 'Block the address for hours, longer if it comes back.', happens: 'The address is blocked for {ban_duration_1}.', order: 10, selected: true, default: true },
			{ type: 'notify_admin', label: 'Notify the administrators.', happens: 'Notify the administrators.', order: 90, selected: false, default: true },
		],
		params: [
			{ name: 'window', type: 'duration', default: 600, min: 60, max: 3600, choices: [], value: 600, label: 'Time window', help: '', unit: '' },
			{ name: 'min_failures', type: 'int', default: 10, min: 3, max: 1000, choices: [], value: 10, label: 'Failed logins', help: '', unit: 'failures' },
			{ name: 'min_names', type: 'int', default: 5, min: 2, max: 1000, choices: [], value: 5, label: 'Different accounts', help: '', unit: 'accounts' },
		],
		cost: { class: 'on_failure_only', text: 'Runs only when a login or share access fails.' },
		requirements: [],
		stores: ['failed_attempts'],
		sendsData: false,
		actsWhileLearning: false,
		simulatable: true,
		stats: { days: 7, detections: 3, enforced: 3, observed: 0, addressesBlocked: 9 },
		...overrides,
	}
}

/**
 * A detection detail as the API returns it.
 *
 * @param overrides - Fields to change
 */
export function makeDetail(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
	return {
		detection: {
			id: 42,
			checkId: 'credential_stuffing',
			checkName: 'Credential stuffing',
			category: 'login_attacks',
			severity: 'medium',
			enforced: true,
			ip: '203.0.113.7',
			netKey: '203.0.113.0/24',
			uid: null,
			shareId: null,
			hits: 1,
			createdAt: 1_790_000_000,
			lastSeenAt: 1_790_000_400,
			userVerdict: null,
		},
		explanation: {},
		actions: [{ type: 'ban', enforced: true, note: null }],
		narrative: {
			title: 'Credential stuffing',
			happened: ['Between 10:02 and 10:09 the address 203.0.113.7 failed to log in 14 times, trying 9 different accounts.'],
			done: ['Blocked 203.0.113.7/32 until 14:09 (reference K7Q2-MPXA, first block).'],
			observedBecause: null,
		},
		text: 'Credential stuffing\n\nBetween 10:02 and 10:09 …',
		attemptsAvailable: true,
		attempts: [{ kind: 'password_login', label: 'Failed password login', uid: 'alice', createdAt: 1_790_000_100 }],
		bans: [{
			id: 7,
			reference: 'K7Q2-MPXA',
			cidr: '203.0.113.7/32',
			scope: 'ip',
			level: 1,
			checkId: 'credential_stuffing',
			checkName: 'Credential stuffing',
			detectionId: 42,
			createdBy: null,
			note: null,
			createdAt: 1_790_000_400,
			expiresAt: 1_790_014_800,
			liftedAt: null,
			liftedBy: null,
			liftNote: null,
			active: true,
		}],
		risk: null,
		...overrides,
	}
}

/**
 * The status of the admin page.
 *
 * @param overrides - Fields to change
 */
export function makeStatus(overrides: Partial<Status> = {}): Status {
	return {
		state: 'learning',
		learning: { active: true, until: 1_790_600_000, daysLeft: 7, minDays: 1, maxDays: 30 },
		checks: { protect: 10, observe: 3, off: 2 },
		last24h: { detections: 1234, enforced: 0, observed: 1234, blockedAddresses: 0, wouldHaveBlocked: 6, accounts: 1, categories: [] },
		activeBans: 2,
		prerequisites: { memoryCache: 'none', mail: false },
		cost: null,
		costSampleRate: 1000,
		problems: [
			{ id: 'mail', level: 'warning', title: 'Nextcloud cannot send emails', text: '', url: null, urlLabel: null },
			{ id: 'cache', level: 'info', title: 'No memory cache', text: '', url: null, urlLabel: null },
		],
		extensions: {},
		...overrides,
	}
}
