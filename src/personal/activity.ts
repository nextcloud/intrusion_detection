/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { SecurityChange } from '../secureAccountTypes.ts'
import type { ActivityItem, Login, SecurityEvent, SignInLabel } from './types.ts'

import { mdiClockAlertOutline, mdiDevices, mdiMapMarkerCheckOutline, mdiMapMarkerQuestionOutline } from '@mdi/js'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'
import { calendarDay } from './time.ts'

export interface ActivityDay {
	/** YYYY-MM-DD */
	day: string
	items: ActivityItem[]
}

/**
 * The timeline in days, newest first, each day's entries newest first.
 *
 * @param items - The timeline as the server sorted it
 */
export function groupByDay(items: ActivityItem[]): ActivityDay[] {
	const days = new Map<string, ActivityItem[]>()
	for (const item of items) {
		const list = days.get(item.day) ?? []
		list.push(item)
		days.set(item.day, list)
	}
	return [...days.entries()]
		.sort(([a], [b]) => b.localeCompare(a))
		.map(([day, list]) => ({ day, items: [...list].sort((a, b) => b.at - a.at) }))
}

/**
 * The day before a calendar day.
 *
 * @param day - YYYY-MM-DD
 */
export function dayBefore(day: string): string {
	const date = new Date(day + 'T12:00:00Z')
	date.setUTCDate(date.getUTCDate() - 1)
	return date.toISOString().slice(0, 10)
}

/**
 * "Today", "Yesterday" or "Wednesday, 15 October".
 *
 * @param day - YYYY-MM-DD
 * @param today - Today in the user's time zone
 */
export function dayLabel(day: string, today: string): string {
	if (day === today) {
		return t(APP_ID, 'Today')
	}
	if (day === dayBefore(today)) {
		return t(APP_ID, 'Yesterday')
	}
	return calendarDay(day, 'long')
}

/**
 * Whether the timeline says anything: the login of this very session
 * alone, as on a brand-new account, is no news.
 *
 * @param items - The timeline
 */
export function hasNews(items: ActivityItem[]): boolean {
	return items.some((item) => !(item.kind === 'login' && item.login?.current))
}

/**
 * Whether an event still waits for "Was this you?".
 *
 * @param event - The event
 */
export function isOpenQuestion(event: SecurityEvent): boolean {
	return event.asks && event.verdict === null
}

/**
 * How the account logged in, in plain words.
 *
 * @param login - The login
 */
export function methodLabel(login: Login): string {
	switch (login.method) {
		case 'password':
			return t(APP_ID, 'Password')
		case 'client_password':
			return t(APP_ID, 'Password in an app')
		case 'app_password':
			return t(APP_ID, 'App password')
		case 'token':
			return t(APP_ID, 'Access token')
		case 'cookie':
			return t(APP_ID, 'Stayed logged in')
		case 'sso':
			return t(APP_ID, 'Single sign-on')
		default:
			return login.method
	}
}

/**
 * How the login was confirmed, or null when it needed nothing.
 *
 * @param login - The login
 */
export function confirmationLabel(login: Login): string | null {
	switch (login.stepUp) {
		case 'pending':
			return t(APP_ID, 'Waiting for confirmation')
		case 'refused':
			return t(APP_ID, 'Refused')
		case 'failed':
			return t(APP_ID, 'Not confirmed')
		case 'allowed':
			return t(APP_ID, 'Allowed without confirmation')
	}
	switch (login.confirmedBy) {
		case 'second_factor':
			return t(APP_ID, 'Confirmed with your second factor')
		case 'email_code':
			return t(APP_ID, 'Confirmed with an email code')
		case 'known_device':
			return t(APP_ID, 'Confirmed by a remembered device')
		case 'admin_approval':
			return t(APP_ID, 'Approved by an administrator')
		default:
			return null
	}
}

/** Who made a change, by its `via` */
const BY: Record<string, () => string> = {
	self: () => t(APP_ID, 'by you'),
	admin: () => t(APP_ID, 'by an administrator'),
	occ: () => t(APP_ID, 'by an administrator on the server'),
	reset: () => t(APP_ID, 'through a password reset'),
	system: () => t(APP_ID, 'by Nextcloud'),
}

/**
 * Who made the change, in words.
 *
 * @param change - The change
 */
export function changedBy(change: SecurityChange): string | null {
	return BY[change.via]?.() ?? null
}

/**
 * The previous and new value, where the change has them.
 *
 * @param change - The change
 */
export function changeValues(change: SecurityChange): string | null {
	if (change.previous && change.new) {
		return t(APP_ID, 'from {previous} to {new}', { previous: change.previous, new: change.new })
	}
	if (change.previous) {
		return t(APP_ID, 'from {previous}', { previous: change.previous })
	}
	return change.new ?? change.detail
}

/** A label of a login, as a badge shows it */
export interface SignInBadge {
	label: SignInLabel
	text: string
	type: 'neutral' | 'info'
	icon: string
}

const BADGES: Record<SignInLabel, () => Omit<SignInBadge, 'label'>> = {
	usual_network: () => ({ text: t(APP_ID, 'Your usual network'), type: 'neutral', icon: mdiMapMarkerCheckOutline }),
	new_network: () => ({ text: t(APP_ID, 'New network'), type: 'info', icon: mdiMapMarkerQuestionOutline }),
	new_device: () => ({ text: t(APP_ID, 'New device'), type: 'info', icon: mdiDevices }),
	unusual_hour: () => ({ text: t(APP_ID, 'Unusual hour'), type: 'info', icon: mdiClockAlertOutline }),
}

/**
 * What the account's own history says about a login, in plain words: a
 * calm badge for the usual network, a noticeable one for anything new.
 * Labels this page does not know are left out.
 *
 * @param labels - The login's labels
 */
export function signInBadges(labels: SignInLabel[]): SignInBadge[] {
	return labels.filter((label) => label in BADGES).map((label) => ({ label, ...BADGES[label]() }))
}
