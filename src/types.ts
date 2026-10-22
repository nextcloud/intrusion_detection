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
	addressesBlocked: number
}

/** Sets every check limit and block duration at once; "custom" after a change by hand */
export type ProtectionLevel = 'recommended' | 'strict' | 'relaxed' | 'custom'

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
	/** What to do about it */
	fix?: string
	/** Documentation, or a place on this page such as "#decoys" */
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

/** What Nextcloud did about a detection: acted, only notified, only recorded, or observed without acting */
export type DetectionOutcome = 'acted' | 'notified' | 'recorded' | 'observed'

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
	/** One plain sentence: what happened and what was done, e.g. "Credential stuffing from 203.0.113.7. The address was blocked." */
	summary: string
	outcome: DetectionOutcome
}

export interface DetectionList {
	detections: Detection[]
	hasMore: boolean
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

export interface RiskPart {
	fact: string
	label: string
	points: number
}

export interface RiskLimit {
	param: string
	label: string
	plain: number
	effective: number
}

/** The address risk score a detection stored, with its parts */
export interface Risk {
	score: number
	tier: 'normal' | 'elevated' | 'high'
	tierLabel: string
	tierElevated: number
	tierHigh: number
	parts: RiskPart[]
	lowered: RiskLimit[]
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
	risk: Risk | null
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
	protectionLevel: ProtectionLevel
	settings: SettingsPayload
	ownAddress: string | null
	docUrl: string
	bruteForceSettingsUrl: string
}

export interface DigestOverview {
	frequency: 'off' | 'daily' | 'weekly'
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

export interface ModeState {
	configured: Mode
	effective: Mode
	reason: string | null
	missing: string | null
	default: Mode
}

export interface CheckRef {
	id: string
	name: string
	mode: ModeState
}

export interface Simulation {
	check: string
	testAddress: string
	mode: Mode
	modeReason: string | null
	runs: boolean
	acts: boolean
	severity: Severity
	narrative: Narrative
	responses: { type: string, text: string }[]
}

export interface Snippet {
	id: string
	file: string
	content: string
}

export interface FirewallExport {
	directory: string | null
	active: boolean
	formats: string[]
	files: string[]
	lastWriteAt: number | null
	error: string | null
	errorText: string | null
	errorAt: number | null
	entries: number
	configKey: string
	snippetsUseDirectory: boolean
	exampleDirectory: string
	snippets: Snippet[]
}

export type ListPurpose = 'deny' | 'hosting' | 'tor'

export interface BlocklistDay {
	day: string
	matches: number
	sample: string[]
}

export interface Blocklist {
	id: string
	name: string
	url: string
	format: string
	purpose: ListPurpose
	mode: 'observe' | 'protect' | null
	enabled: boolean
	builtin: boolean
	interval: number
	customInterval: boolean
	termsUrl: string | null
	reference: string | null
	ranges: number
	entries: number
	skipped: number
	lastAttemptAt: number | null
	lastSuccessAt: number | null
	lastFailureAt: number | null
	lastError: string | null
	lastErrorText: string | null
	failures: number
	stale: boolean
	matches: BlocklistDay[]
}

export interface Blocklists {
	lists: Blocklist[]
	countsMatches: boolean
	matchDays: number
	check: CheckRef
	/** The check that uses the network lists */
	networkCheck: CheckRef
	maxLists: number
	minInterval: number
	maxInterval: number
	formats: string[]
}

export interface SyncResult {
	list: string
	outcome: 'updated' | 'unchanged' | 'failed' | 'skipped'
	error: string | null
	errorText: string | null
	ranges: number
}

export type DecoyFormat = 'app-password' | 'token'

export interface Decoy {
	id: number
	label: string
	loginName: string | null
	format: DecoyFormat
	createdBy: string | null
	createdAt: number
	lastTriggeredAt: number | null
	triggerCount: number
}

export interface NewDecoy {
	decoy: Decoy
	secret: string
}

export interface ReservedNames {
	names: string[]
	suggestions: string[]
	collisions: string[]
	max: number
}

/** A web server setup, as far as it decides which trap paths reach Nextcloud */
export type TrapWebServer = 'nginx' | 'apache_fpm' | 'apache' | 'unknown'

export interface TrapPathList {
	builtinEnabled: boolean
	/** answeredBy: the web servers that answer the path themselves unless the rule hands it to Nextcloud */
	builtin: { path: string, text: string, answeredBy: ('nginx' | 'apache_fpm')[] }[]
	autodiscover: boolean
	autodiscoverPath: string
	custom: string[]
	/** The web server that served this page */
	webServer: TrapWebServer
	/** The enabled trap paths that reach Nextcloud on this web server only with the rule */
	needRule: string[]
	max: number
	snippets: Snippet[]
	snippetsSkipped: string[]
}

export interface Traps {
	decoys: Decoy[]
	decoyCheck: CheckRef
	reservedCheck: CheckRef
	trapCheck: CheckRef
	decoyCollisions: string[]
	reservedNames: ReservedNames
	trapPaths: TrapPathList
}

export interface Recipient {
	uid: string
	displayName: string
	hasEmail: boolean
}

export interface CheckNotifications {
	id: string
	name: string
	category: string
	mode: Mode
	admin: boolean
	user: boolean
	adminAvailable: boolean
	userAvailable: boolean
}

export interface Notifications {
	recipients: Recipient[]
	recipientLimit: number
	mail: boolean
	me: { uid: string, email: string | null, recipient: boolean }
	checks: CheckNotifications[]
}

export interface TestAlertResult {
	bell: boolean
	email: 'sent' | 'no_address' | 'no_mail' | 'failed'
	address: string | null
}

export interface StoredData {
	id: string
	name: string
	what: string
	why: string
	retention: string
	where: string
	checks: string[]
}

export interface OutgoingData {
	id: string
	name: string
	text: string
	active: boolean
	items: string[]
}

export interface Privacy {
	stored: StoredData[]
	outgoing: OutgoingData[]
	gdpr: string[]
}

export interface Signature {
	id: string
	weight: number
	scope: 'any' | 'encoded'
	requiresOther: boolean
	description: string
	group: 'sql' | 'payload'
	enabled: boolean
}

export interface CustomSignature {
	entry: string
	id: string
	weight: number
	pattern: string
	problem: string | null
	problemText: string | null
}

export interface Signatures {
	version: number
	minWeight: number
	signatures: Signature[]
	custom: CustomSignature[]
	maxCustom: number
	maxLength: number
	defaultWeight: number
}

export interface SignatureMatch {
	id: string
	weight: number
	description: string
}

export interface PayloadForm {
	encoding: 'none' | 'base64' | 'base64_twice'
	text: string
	weight: number
	matches: SignatureMatch[]
}

export interface PayloadValue {
	location: 'path' | 'query' | 'form'
	name: string
	skipped: string | null
	truncated: boolean
	normalised?: string
	decoded?: string[]
	forms?: PayloadForm[]
	weight?: number
	fires?: boolean
}

export interface PayloadTest {
	kind: 'url' | 'value'
	prefilter: boolean
	pathExcluded: boolean
	minWeight: number
	maxBytes: number
	signaturesVersion: number
	fires: boolean
	modes: { anonymous: Mode, authenticated: Mode }
	values: PayloadValue[]
}

export type IncidentSubjectType = 'user' | 'address'

export interface IncidentRequest {
	/** The account or the address */
	type: IncidentSubjectType
	value: string
	/** Unix times; null for the default period (the 7 days before now) */
	since: number | null
	until: number | null
}

export interface IncidentEntry {
	id: string
	at: number
	/** When a state with an end, such as a block, ends or ended */
	endsAt: number | null
	/** When a repeated event was last seen */
	lastSeenAt: number | null
	kind: string
	group: string
	title: string
	severity: Severity | null
	enforced: boolean | null
	/** What Nextcloud did about a detection; null for other entries */
	outcome: DetectionOutcome | null
	details: string[]
	done: string[]
	note: string | null
	address: string | null
	accounts: string[]
	ref: { type: string, id: string } | null
}

export interface IncidentSummary {
	headline: string
	happened: string[]
	startedAt: number | null
	foundAt: number | null
	lastActivityAt: number | null
	affected: string[]
	dataCategories: string[]
	dataNote: string | null
	measures: string[]
	openItems: string[]
	/** enforced: not only observed; acted: an action other than a notification ran */
	counts: { entries: number, detections: number, enforced: number, acted: number, observed: number }
}

export interface IncidentReport {
	schemaVersion: number
	generatedAt: number
	generatedBy: string
	server: string
	subject: { type: IncidentSubjectType, value: string, displayName: string | null }
	period: { since: number, until: number }
	summary: IncidentSummary
	kinds: { id: string, label: string, count: number }[]
	entries: IncidentEntry[]
	notes: { id: string, text: string, url: string | null, linkLabel: string | null }[]
	truncated: boolean
	maxEntries: number
}

export type ConfirmationMethodId = 'second_factor' | 'known_device' | 'email_code' | 'admin_approval'

export interface ConfirmationMethod {
	id: ConfirmationMethodId
	name: string
	description: string
	state: 'on' | 'off' | 'unavailable'
	note: string | null
}

export interface ConfirmationPolicy {
	id: string
	label: string
	why: string
	default: string
	outcome: string
	/** The global setting that holds the outcome */
	setting: string
	knownDevice: boolean
	/** False for reasons a remembered device can never confirm */
	knownDeviceAllowed: boolean
}

export interface ConfirmationOutcome {
	id: string
	label: string
	description: string
}

export interface LoginApproval {
	id: number
	uid: string
	displayName: string
	ip: string | null
	createdAt: number
	expiresAt: number
	canDecide: boolean
}

/** An account waiting to become an administrator until another administrator approves */
export interface AdminGrantRequest {
	id: number
	uid: string
	displayName: string
	group: string
	requestedBy: string
	requesterName: string
	createdAt: number
	expiresAt: number
	/** Whether this administrator may approve: neither the one who asked nor the account */
	canApprove: boolean
}

/** The outcome of every reason at once; "custom" when they were set per reason */
export type ConfirmationPreset = 'recommended' | 'refuse' | 'allow'

export interface ConfirmationPresetResult {
	preset: ConfirmationPreset | 'custom'
	policies: ConfirmationPolicy[]
}

export interface ConfirmationOverview {
	methods: ConfirmationMethod[]
	policies: ConfirmationPolicy[]
	preset: ConfirmationPreset | 'custom'
	outcomes: ConfirmationOutcome[]
	users: { withoutMethod: number, active: number }
	admins: { total: number, withoutEmail: number, withoutSecondFactor: number, withNeither: string[] }
	approvers: number
	approvals: LoginApproval[]
}

export interface UnconfirmableAccount {
	uid: string
	displayName: string
	lastLogin: number
	groups: string[]
	admin: boolean
}
