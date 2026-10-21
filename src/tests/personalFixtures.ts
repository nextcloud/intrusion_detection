/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { KnownDevice, Login, PersonalOverview, SecurityEvent, TrustedNetwork } from '../personal/types.ts'

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
		id,
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
		id,
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
		id,
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
		id,
		network: '203.0.113.0/24',
		createdAt: NOW - 86400,
		expiresAt: NOW + 29 * 86400,
		detectionId: 4,
		...overrides,
	}
}
