/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ActivityItem, KnownDevice, Login, PersonalActivity, PersonalOverview, SecurityEvent, TrustedNetwork } from '../personal/types.ts'
import type { SecurityChange } from '../secureAccountTypes.ts'

import { snowflake } from './fixtures.ts'

/** 2026-10-21 12:00 UTC */
export const NOW = Date.UTC(2026, 9, 21, 12, 0) / 1000

/**
 * Thirty days of failed logins, oldest first, all zero unless given.
 *
 * @param counts - Counts by index, 29 is today
 */
export function failedDays(counts: Record<number, number> = {}): PersonalOverview['failedLogins']['days'] {
	return Array.from({ length: 30 }, (_, i) => {
		const start = NOW - (29 - i) * 86400
		return { day: new Date(start * 1000).toISOString().slice(0, 10), start, count: counts[i] ?? 0 }
	})
}

/**
 * @param overrides - Fields to change
 */
export function overview(overrides: Partial<PersonalOverview> = {}): PersonalOverview {
	return {
		status: { level: 'ok', headline: 'No unusual activity in the last 30 days', items: [] },
		failedLogins: { days: failedDays(), total: 0, places: 0, placesCapped: false, recent: [], timezone: 'Europe/Berlin' },
		emailHint: null,
		timezone: 'Europe/Berlin',
		...overrides,
	}
}

/**
 * @param id - The event id
 * @param overrides - Fields to change
 */
export function securityEvent(id: number, overrides: Partial<SecurityEvent> = {}): SecurityEvent {
	return {
		id: snowflake(id),
		check: 'second_factor_failed',
		severity: 'high',
		enforced: true,
		createdAt: NOW - 3600 * id,
		lastSeenAt: NOW - 3600 * id,
		hits: 1,
		subject: 'Someone entered your password but failed the second factor ' + id,
		happened: ['Someone entered your correct password, then failed the second factor 3 times.'],
		when: 'This happened on 21 October 2026 at 13:00, from the address 203.0.113.7, with "Firefox".',
		done: ['The suspicious session was ended.'],
		advice: ['Change your password.'],
		address: '203.0.113.7',
		asks: false,
		verdict: null,
		verdictAt: null,
		canConfirm: false,
		...overrides,
	}
}

/**
 * @param id - The login id
 * @param overrides - Fields to change
 */
export function login(id: number, overrides: Partial<Login> = {}): Login {
	return {
		id: snowflake(id),
		createdAt: NOW - 600 * id,
		ip: '198.51.100.' + id,
		network: '198.51.100.0/24',
		userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0',
		method: 'password',
		knownDevice: false,
		confirmedBy: 'none',
		stepUp: null,
		current: false,
		device: 'Firefox on Linux',
		...overrides,
	}
}

/**
 * @param id - The device id
 * @param overrides - Fields to change
 */
export function knownDevice(id: number, overrides: Partial<KnownDevice> = {}): KnownDevice {
	return {
		id: snowflake(id),
		label: 'Firefox on Linux',
		family: 'firefox',
		platform: 'linux',
		network: '198.51.100.0/24',
		createdAt: NOW - 86400 * 10,
		lastSeenAt: NOW - 3600,
		current: false,
		...overrides,
	}
}

/**
 * @param id - The entry id
 * @param overrides - Fields to change
 */
export function trustedNetwork(id: number, overrides: Partial<TrustedNetwork> = {}): TrustedNetwork {
	return {
		id: snowflake(id),
		network: '203.0.113.0/24',
		createdAt: NOW - 86400,
		expiresAt: NOW + 29 * 86400,
		detectionId: snowflake(4),
		...overrides,
	}
}

/**
 * @param id - The change id
 * @param overrides - Fields to change
 */
export function securityChange(id: number, overrides: Partial<SecurityChange> = {}): SecurityChange {
	return {
		id: snowflake(id),
		type: 'password_changed',
		label: 'Password changed',
		via: 'self',
		actor: null,
		previous: null,
		new: null,
		detail: null,
		address: '198.51.100.12',
		createdAt: NOW - 1800 * id,
		...overrides,
	}
}

/**
 * The UTC day of a time, as the fixtures' user lives in UTC.
 *
 * @param at - Seconds since the epoch
 */
function dayOf(at: number): string {
	return new Date(at * 1000).toISOString().slice(0, 10)
}

/**
 * A timeline entry around one of the other fixtures.
 *
 * @param of - What the entry is
 */
export function activityItem(of: { login: Login } | { change: SecurityChange } | { event: SecurityEvent } | { failed: number, at: number }): ActivityItem {
	const base = { login: null, change: null, failedLogins: null, event: null }
	if ('login' in of) {
		return { ...base, id: 'login-' + of.login.id, kind: 'login', at: of.login.createdAt, day: dayOf(of.login.createdAt), login: of.login }
	}
	if ('change' in of) {
		return { ...base, id: 'change-' + of.change.id, kind: 'change', at: of.change.createdAt, day: dayOf(of.change.createdAt), change: of.change }
	}
	if ('event' in of) {
		return { ...base, id: 'event-' + of.event.id, kind: 'event', at: of.event.createdAt, day: dayOf(of.event.createdAt), event: of.event }
	}
	return { ...base, id: 'failed-' + dayOf(of.at), kind: 'failed_logins', at: of.at, day: dayOf(of.at), failedLogins: { count: of.failed } }
}

/**
 * @param overrides - Fields to change
 */
export function activity(overrides: Partial<PersonalActivity> = {}): PersonalActivity {
	return {
		questions: [],
		items: [],
		hasMore: false,
		today: dayOf(NOW),
		timezone: 'UTC',
		...overrides,
	}
}
