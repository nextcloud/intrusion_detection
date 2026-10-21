/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** The shapes of the admin API, see `lib/ResponseDefinitions.php`. */

export type Mode = 'off' | 'observe' | 'protect'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type ParamType = 'int' | 'duration' | 'float' | 'bool' | 'choice' | 'string_list' | 'cidr_list'
export type ParamValue = number | boolean | string | string[]

export interface Param {
	name: string
	type: ParamType
	default: ParamValue
	min: number | null
	max: number | null
	choices: string[]
	value: ParamValue
	label: string
	help: string
	unit: string
}

export interface CheckResponse {
	type: string
	label: string
	happens: string
	order: number
	selected: boolean
	default: boolean
}

export interface Requirement {
	id: string
	met: boolean
	text: string
}

export interface CheckStats {
	days: number
	detections: number
	enforced: number
	observed: number
	fired: number
	addressesBlocked: number
}

export interface Check {
	id: string
	category: string
	internal: boolean
	severity: Severity
	mode: {
		configured: Mode
		effective: Mode
		reason: 'disabled' | 'learning' | 'requirement' | null
		missing: string | null
		default: Mode
	}
	texts: {
		name: string
		summary: string
		detects: string
		decides: string
		wrong: string
		data: string
	}
	decidesTemplate: string
	decides: string
	happens: string[]
	responses: CheckResponse[]
	params: Param[]
	cost: { class: string, text: string }
	requirements: Requirement[]
	stores: string[]
	sendsData: boolean
	actsWhileLearning: boolean
	simulatable: boolean
	stats: CheckStats
}

export interface Category {
	id: string
	name: string
}

export interface CheckList {
	checks: Check[]
	categories: Category[]
}

export interface Learning {
	active: boolean
	until: number
	daysLeft: number
	minDays: number
	maxDays: number
}

export interface Problem {
	id: string
	level: 'info' | 'warning' | 'error'
	title: string
	text: string
	url: string | null
	urlLabel: string | null
}

export interface Status {
	state: 'protecting' | 'learning' | 'off'
	learning: Learning
	checks: { protect: number, observe: number, off: number }
	last24h: {
		detections: number
		enforced: number
		observed: number
		blockedAddresses: number
		wouldHaveBlocked: number
		accounts: number
		categories: { id: string, name: string, enforced: number, observed: number }[]
	}
	activeBans: number
	prerequisites: { memoryCache: 'distributed' | 'local' | 'none', mail: boolean }
	cost: { samples: number, averageMicroseconds: number, maxMicroseconds: number } | null
	costSampleRate: number
	problems: Problem[]
	extensions: Record<string, Record<string, unknown>>
}

export interface Detection {
	id: number
	checkId: string
	checkName: string
	category: string
	severity: Severity
	enforced: boolean
	ip: string | null
	netKey: string | null
	uid: string | null
	shareId: number | null
	hits: number
	createdAt: number
	lastSeenAt: number
	userVerdict: string | null
}

export interface DetectionList {
	detections: Detection[]
	total: number
}

export interface Narrative {
	title: string
	happened: string[]
	done: string[]
	observedBecause: string | null
}

export interface Attempt {
	kind: string
	label: string
	uid: string | null
	createdAt: number
}

export interface Ban {
	id: number
	reference: string
	cidr: string
	scope: 'ip' | 'net'
	level: number
	checkId: string
	checkName: string
	detectionId: number | null
	createdBy: string | null
	note: string | null
	createdAt: number
	expiresAt: number
	liftedAt: number | null
	liftedBy: string | null
	liftNote: string | null
	active: boolean
}

export interface BanList {
	bans: Ban[]
	hasMore: boolean
	activeCount: number
}

export interface DetectionDetail {
	detection: Detection
	explanation: Record<string, unknown>
	actions: { type: string, enforced: boolean, note: string | null }[]
	narrative: Narrative
	text: string
	attemptsAvailable: boolean
	attempts: Attempt[]
	bans: Ban[]
}

export interface LookupResult {
	kind: 'reference' | 'address' | 'user' | 'none'
	query: string
	bans: Ban[]
	detections: Detection[]
	user: { uid: string, displayName: string } | null
}

export interface GlobalSetting extends Param {
	group: string
}

export interface SettingsPayload {
	settings: GlobalSetting[]
	templates: Record<string, string>
}

export interface Day {
	day: string
	start: number
	enforced: number
	observed: number
	categories: Record<string, { enforced: number, observed: number }>
}

export interface DailyStats {
	days: Day[]
	timezone: string
}

export interface DetectionFilters {
	check: string
	severity: string
	user: string
	address: string
	mode: '' | 'enforced' | 'observed'
}

export interface InitialState {
	status: Status
	checks: CheckList
	settings: SettingsPayload
	ownAddress: string | null
	docUrl: string
	bruteForceSettingsUrl: string
}

export interface DigestOverview {
	frequency: 'off' | 'daily' | 'weekly'
	sendQuiet: boolean
	timezone: string
	nextDue: number | null
	last: { period: number, sentAt: number, result: string, recipients: number, failed: number } | null
	recipients: number
	withoutEmail: { uid: string, displayName: string }[]
	withoutEmailCount: number
	mailConfigured: boolean
	viewerHasEmail: boolean
}

export interface WebhookEvent {
	class: string
	name: string
	description: string
	example: Record<string, unknown>
}

export interface WebhookEvents {
	includeIp: boolean
	webhooksEnabled: boolean
	events: WebhookEvent[]
}
