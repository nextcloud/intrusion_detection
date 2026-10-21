/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { getCanonicalLocale } from '@nextcloud/l10n'

/**
 * Format with the user's own time zone setting, as the server uses it for
 * notifications and emails; the browser's time zone if that one is unknown.
 *
 * @param timestamp - Seconds since the epoch
 * @param options - What to show
 * @param timeZone - The user's time zone
 */
function format(timestamp: number, options: Intl.DateTimeFormatOptions, timeZone?: string): string {
	try {
		return new Intl.DateTimeFormat(getCanonicalLocale(), { ...options, timeZone }).format(timestamp * 1000)
	} catch {
		return new Intl.DateTimeFormat(getCanonicalLocale(), options).format(timestamp * 1000)
	}
}

/**
 * "21 October 2026 at 14:03"
 *
 * @param timestamp - Seconds since the epoch
 * @param timeZone - The user's time zone
 */
export function dateTime(timestamp: number, timeZone?: string): string {
	return format(timestamp, { dateStyle: 'long', timeStyle: 'short' }, timeZone)
}

/**
 * "21 October 2026"
 *
 * @param timestamp - Seconds since the epoch
 * @param timeZone - The user's time zone
 */
export function date(timestamp: number, timeZone?: string): string {
	return format(timestamp, { dateStyle: 'long' }, timeZone)
}

/**
 * A day of the user's own calendar, which needs no time zone.
 *
 * @param day - YYYY-MM-DD
 * @param style - "21 Oct" or "Wednesday, 21 October"
 */
export function calendarDay(day: string, style: 'short' | 'long'): string {
	const options: Intl.DateTimeFormatOptions = style === 'short'
		? { day: 'numeric', month: 'short', timeZone: 'UTC' }
		: { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' }
	return new Date(day + 'T12:00:00Z').toLocaleDateString(getCanonicalLocale(), options)
}
