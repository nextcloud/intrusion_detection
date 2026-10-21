/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** The shapes of the personal API, see `lib/ResponseDefinitions.php`. */

import type { SecurityChange } from '../secureAccountTypes.ts'

export type StatusLevel = 'ok' | 'info' | 'warning'

export interface StatusItem {
	id: string
	level: 'info' | 'warning'
	text: string
	at: number | null
}

export interface PersonalStatus {
	level: StatusLevel
	headline: string
	items: StatusItem[]
}

export interface FailedLoginDay {
	/** The user's own day, YYYY-MM-DD */
	day: string
	start: number
	count: number
}

export interface FailedLogins {
	days: FailedLoginDay[]
	total: number
	places: number
	placesCapped: boolean
	recent: { address: string, lastSeenAt: number }[]
	timezone: string
}

export interface EmailHint {
	emailUrl: string
	secondFactorUrl: string | null
}

export interface PersonalOverview {
	status: PersonalStatus
	failedLogins: FailedLogins
	emailHint: EmailHint | null
	timezone: string
}

export type Verdict = 'confirmed' | 'denied'

export interface SecurityEvent {
	id: number
	check: string
	severity: string
	enforced: boolean
	createdAt: number
	lastSeenAt: number
	hits: number
	subject: string
	happened: string[]
	when: string
	done: string[]
	advice: string[]
	address: string | null
	asks: boolean
	verdict: Verdict | null
	verdictAt: number | null
	canConfirm: boolean
}

export interface Login {
	id: number
	createdAt: number
	ip: string | null
	network: string | null
	userAgent: string | null
	method: string
	knownDevice: boolean
	confirmedBy: string
	stepUp: string | null
	current: boolean
	device: string
}

export interface KnownDevice {
	id: number
	label: string
	family: string
	platform: string
	network: string | null
	createdAt: number
	lastSeenAt: number
	current: boolean
}

export interface TrustedNetwork {
	id: number
	network: string
	createdAt: number
	expiresAt: number
	detectionId: number | null
}

export interface LoggedOutElsewhere {
	sessions: number
	devices: number
}

export type ActivityKind = 'login' | 'change' | 'failed_logins' | 'event'

/** One entry of the timeline; the field named by `kind` is set */
export interface ActivityItem {
	id: string
	kind: ActivityKind
	at: number
	/** The user's own day, YYYY-MM-DD */
	day: string
	login: Login | null
	change: SecurityChange | null
	failedLogins: { count: number } | null
	event: SecurityEvent | null
}

export interface PersonalActivity {
	/** The open "Was this you?" questions */
	questions: SecurityEvent[]
	/** Everything else, newest first */
	items: ActivityItem[]
	hasMore: boolean
	/** Today in the user's time zone, YYYY-MM-DD */
	today: string
	timezone: string
}

/** What "Manage" has to offer */
export interface ManageSummary {
	devices: number
	networks: number
	otherBrowsers: number
}

/** What the page comes with */
export interface PersonalState {
	overview: PersonalOverview
	manage: ManageSummary
}
