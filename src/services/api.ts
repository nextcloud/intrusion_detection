/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { OCSResponse } from '@nextcloud/typings/ocs'
import type {
	AdminGrantRequest,
	Ban,
	BanList,
	Blocklist,
	Blocklists,
	Check,
	CheckList,
	ConfirmationOverview,
	ConfirmationPreset,
	ConfirmationPresetResult,
	CustomSignature,
	DailyStats,
	DecoyFormat,
	DetectionDetail,
	DetectionFilters,
	DetectionList,
	DigestOverview,
	FirewallExport,
	IncidentReport,
	IncidentRequest,
	Learning,
	LoginApproval,
	LookupResult,
	Mode,
	NewDecoy,
	Notifications,
	ParamValue,
	PayloadTest,
	Privacy,
	ProtectionLevel,
	ReservedNames,
	SettingsPayload,
	Signatures,
	Simulation,
	Status,
	SyncResult,
	TestAlertResult,
	TrapPathList,
	Traps,
	UnconfirmableAccount,
	WebhookEvents,
} from '../types.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { PasswordConfirmationCancelledError, PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { generateOcsUrl } from '@nextcloud/router'

/**
 * An error the API explained: the translated message, the setting it is
 * about, and the machine-readable reason.
 */
export class ApiError extends Error {
	constructor(
		message: string,
		public readonly param: string | null = null,
		options?: ErrorOptions,
		public readonly reason: string | null = null,
	) {
		super(message, options)
	}
}

/**
 * Whether the admin closed the password dialog: nothing went wrong, nothing was changed.
 *
 * @param error - The error a write threw
 */
export function isCancelled(error: unknown): boolean {
	return error instanceof PasswordConfirmationCancelledError
}

/**
 * Whether the server refused the request because too many came in a short time.
 *
 * @param error - The error a request threw
 */
export function isRateLimited(error: unknown): boolean {
	const cause = error instanceof ApiError ? error.cause : error
	return isAxiosError(cause) && cause.response?.status === 429
}

/**
 * The message to show for a failed request.
 *
 * @param error - The error
 * @param fallback - What to say when the server did not explain it
 */
export function errorMessage(error: unknown, fallback: string): string {
	return error instanceof ApiError ? error.message : fallback
}

/**
 * @param path - Path below the app's API
 */
function url(path: string): string {
	return generateOcsUrl('apps/intrusion_detection/api/v1/' + path)
}

interface RequestOptions {
	/** Query parameters */
	params?: Record<string, unknown>
	/** The request body */
	data?: unknown
	/** The request needs a recent password confirmation; the page asks for it when needed */
	confirm?: boolean
	/** Cancels the request */
	signal?: AbortSignal
}

/**
 * Send a request to the app's API and unwrap the OCS envelope; errors
 * become `ApiError` where the server explained them.
 *
 * @param method - The HTTP method
 * @param path - Path below the app's API
 * @param options - Parameters, body, password confirmation and cancellation
 */
export async function call<T>(method: 'get' | 'post' | 'put' | 'delete', path: string, options: RequestOptions = {}): Promise<T> {
	const { params, data, confirm, signal } = options
	try {
		const response = await axios.request<OCSResponse<T>>({
			method,
			url: url(path),
			params,
			data,
			signal,
			...(confirm ? { confirmPassword: PwdConfirmationMode.Lax } : {}),
		})
		return response.data.ocs.data
	} catch (error) {
		throw explained(error)
	}
}

type OcsError = OCSResponse<{ message?: string, param?: string | null, reason?: string } | undefined>['ocs']

/**
 * The error as `ApiError` when the OCS answer explains it, else as it is.
 *
 * @param error - What a request threw
 * @param ocs - The OCS envelope of the answer; read from the error when not given
 */
function explained(error: unknown, ocs?: OcsError): unknown {
	const body = ocs ?? (isAxiosError(error) ? (error.response?.data as { ocs?: OcsError } | undefined)?.ocs : undefined)
	const message = body?.data?.message || body?.meta?.message
	return message ? new ApiError(message, body?.data?.param ?? null, { cause: error }, body?.data?.reason ?? null) : error
}

/**
 * @param signal - Cancels the request
 */
export function fetchStatus(signal?: AbortSignal): Promise<Status> {
	return call<Status>('get', 'status', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchChecks(signal?: AbortSignal): Promise<CheckList> {
	return call<CheckList>('get', 'checks', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchProtectionLevel(signal?: AbortSignal): Promise<{ level: ProtectionLevel }> {
	return call<{ level: ProtectionLevel }>('get', 'protection-level', { signal })
}

/**
 * Set every check limit and block duration to a level.
 *
 * @param level - The level
 */
export function updateProtectionLevel(level: Exclude<ProtectionLevel, 'custom'>): Promise<{ level: ProtectionLevel, checks: CheckList }> {
	return call<{ level: ProtectionLevel, checks: CheckList }>('put', 'protection-level', { data: { level }, confirm: true })
}

/**
 * @param id - The check id
 * @param change - What to change
 * @param change.mode - The new mode
 * @param change.responses - The responses to run
 * @param change.params - New setting values by name
 */
export function updateCheck(id: string, change: { mode?: Mode, responses?: string[], params?: Record<string, ParamValue> }): Promise<Check> {
	return call<Check>('put', 'checks/' + encodeURIComponent(id), { data: change, confirm: true })
}

/**
 * @param id - The check id
 */
export function resetCheck(id: string): Promise<Check> {
	return call<Check>('post', 'checks/' + encodeURIComponent(id) + '/reset', { data: {}, confirm: true })
}

/**
 * @param filters - The filters
 * @param limit - Page size
 * @param offset - Page start
 * @param since - Only detections since this Unix time
 * @param signal - Cancels the request
 */
export function fetchDetections(filters: Partial<DetectionFilters>, limit = 25, offset = 0, since = 0, signal?: AbortSignal): Promise<DetectionList> {
	return call<DetectionList>('get', 'detections', { params: { ...filters, limit, offset, since }, signal })
}

/**
 * @param id - The detection id
 * @param signal - Cancels the request
 */
export function fetchDetection(id: number, signal?: AbortSignal): Promise<DetectionDetail> {
	return call<DetectionDetail>('get', 'detections/' + id, { signal })
}

/**
 * @param days - How many days
 * @param signal - Cancels the request
 */
export function fetchDailyStats(days = 30, signal?: AbortSignal): Promise<DailyStats> {
	return call<DailyStats>('get', 'stats/daily', { params: { days }, signal })
}

/**
 * @param all - Also ended and lifted blocks
 * @param limit - Page size
 * @param offset - Page start
 * @param signal - Cancels the request
 */
export function fetchBans(all = false, limit = 50, offset = 0, signal?: AbortSignal): Promise<BanList> {
	return call<BanList>('get', 'bans', { params: { all: all ? 1 : 0, limit, offset }, signal })
}

/**
 * @param ban - The block to add
 * @param ban.target - Address or network
 * @param ban.level - Escalation level
 * @param ban.duration - Duration in seconds instead of the level's
 * @param ban.note - Why
 */
export function addBan(ban: { target: string, level: number, duration?: number, note: string }): Promise<Ban> {
	return call<Ban>('post', 'bans', { data: ban, confirm: true })
}

/**
 * @param id - The block id
 * @param note - Why it is lifted
 */
export function liftBan(id: number, note: string): Promise<Ban> {
	return call<Ban>('delete', 'bans/' + id, { data: { note }, confirm: true })
}

/**
 * @param q - A reference, an address or an account
 * @param signal - Cancels the request
 */
export function lookup(q: string, signal?: AbortSignal): Promise<LookupResult> {
	return call<LookupResult>('get', 'lookup', { params: { q }, signal })
}

/**
 * @param action - What to do
 * @param days - For start and extend
 */
export function updateLearning(action: 'start' | 'extend' | 'stop', days = 7): Promise<Learning> {
	return call<Learning>('put', 'learning', { data: { action, days }, confirm: true })
}

/**
 * @param signal - Cancels the request
 */
export function fetchSettings(signal?: AbortSignal): Promise<SettingsPayload> {
	return call<SettingsPayload>('get', 'settings', { signal })
}

/**
 * @param values - New values by setting name
 */
export function updateSettings(values: Record<string, ParamValue>): Promise<SettingsPayload> {
	return call<SettingsPayload>('put', 'settings', { data: { values }, confirm: true })
}

export const resetSettings = () => call<SettingsPayload>('post', 'settings/reset', { data: {}, confirm: true })

export const exportSettings = () => call<Record<string, unknown>>('get', 'settings/export')

/**
 * @param signal - Cancels the request
 */
export function fetchDigest(signal?: AbortSignal): Promise<DigestOverview> {
	return call<DigestOverview>('get', 'digest', { signal })
}

export const sendTestDigest = () => call<{ message: string }>('post', 'digest/test', { data: {}, confirm: true })

/**
 * @param signal - Cancels the request
 */
export function fetchWebhookEvents(signal?: AbortSignal): Promise<WebhookEvents> {
	return call<WebhookEvents>('get', 'events', { signal })
}

/**
 * @param id - The check id
 * @param signal - Cancels the request
 */
export function simulateCheck(id: string, signal?: AbortSignal): Promise<Simulation> {
	return call<Simulation>('get', 'checks/' + encodeURIComponent(id) + '/simulation', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchExport(signal?: AbortSignal): Promise<FirewallExport> {
	return call<FirewallExport>('get', 'export', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchBlocklists(signal?: AbortSignal): Promise<Blocklists> {
	return call<Blocklists>('get', 'blocklists', { signal })
}

/**
 * @param list - The new list
 * @param list.id - Its short name
 * @param list.url - Where to download it
 * @param list.purpose - Block, or mark as hosting or Tor
 * @param list.format - The file format
 * @param list.mode - For blocklists: observe or protect
 * @param list.sha256 - The SHA-256 the file must have, or null to trust the publisher and https
 */
export function createBlocklist(list: { id: string, url: string, purpose: string, format: string, mode: string, sha256: string | null }): Promise<Blocklist> {
	const { format, ...rest } = list
	// "format" would choose the OCS response format
	return call<Blocklist>('post', 'blocklists', { data: { ...rest, fileFormat: format }, confirm: true })
}

/**
 * @param id - The list
 * @param change - What to change
 * @param change.enabled - Use the list
 * @param change.mode - Observe or protect
 * @param change.interval - Seconds between downloads, 0 for the default
 * @param change.sha256 - Your own list: the SHA-256 the file must have, '' to trust the publisher and https
 */
export function updateBlocklist(id: string, change: { enabled?: boolean, mode?: string, interval?: number, sha256?: string }): Promise<Blocklist> {
	return call<Blocklist>('put', 'blocklists/' + encodeURIComponent(id), { data: change, confirm: true })
}

/**
 * @param id - The list
 */
export function removeBlocklist(id: string): Promise<{ removed: string }> {
	return call<{ removed: string }>('delete', 'blocklists/' + encodeURIComponent(id), { confirm: true })
}

/**
 * @param id - The list
 */
export function syncBlocklist(id: string): Promise<{ result: SyncResult, list: Blocklist }> {
	return call<{ result: SyncResult, list: Blocklist }>('post', 'blocklists/' + encodeURIComponent(id) + '/sync', { data: {}, confirm: true })
}

/**
 * @param signal - Cancels the request
 */
export function fetchTraps(signal?: AbortSignal): Promise<Traps> {
	return call<Traps>('get', 'decoys', { signal })
}

/**
 * @param decoy - The decoy to create
 * @param decoy.label - Where it is planted
 * @param decoy.loginName - An optional login name no account uses
 * @param decoy.format - What the secret looks like
 */
export function createDecoy(decoy: { label: string, loginName: string, format: DecoyFormat }): Promise<NewDecoy> {
	// "format" would choose the OCS response format
	return call<NewDecoy>('post', 'decoys', { data: { label: decoy.label, loginName: decoy.loginName, secretFormat: decoy.format }, confirm: true })
}

/**
 * @param id - The decoy
 */
export function deleteDecoy(id: number): Promise<{ deleted: number }> {
	return call<{ deleted: number }>('delete', 'decoys/' + id, { confirm: true })
}

/**
 * @param change - Names to reserve and to release
 * @param change.add - Names to reserve
 * @param change.remove - Names to release
 */
export function updateReservedNames(change: { add?: string[], remove?: string[] }): Promise<ReservedNames> {
	return call<ReservedNames>('put', 'reserved-names', { data: change, confirm: true })
}

/**
 * @param change - What to change
 * @param change.add - Paths to add
 * @param change.remove - Paths to remove
 * @param change.builtinEnabled - Use the built-in list
 * @param change.autodiscover - Trap the autodiscover path
 */
export function updateTrapPaths(change: { add?: string[], remove?: string[], builtinEnabled?: boolean, autodiscover?: boolean }): Promise<TrapPathList> {
	return call<TrapPathList>('put', 'trap-paths', { data: change, confirm: true })
}

/**
 * @param signal - Cancels the request
 */
export function fetchNotifications(signal?: AbortSignal): Promise<Notifications> {
	return call<Notifications>('get', 'notifications', { signal })
}

export const sendTestAlert = () => call<TestAlertResult>('post', 'notifications/test', { data: {}, confirm: true })

/**
 * @param signal - Cancels the request
 */
export function fetchPrivacy(signal?: AbortSignal): Promise<Privacy> {
	return call<Privacy>('get', 'privacy', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchSignatures(signal?: AbortSignal): Promise<Signatures> {
	return call<Signatures>('get', 'payload/signatures', { signal })
}

/**
 * @param entries - Custom signatures to check before saving
 */
export function checkSignatures(entries: string[]): Promise<{ entries: CustomSignature[] }> {
	return call<{ entries: CustomSignature[] }>('post', 'payload/signatures/check', { data: { entries } })
}

/**
 * @param input - A URL or a value
 */
export function testPayload(input: string): Promise<PayloadTest> {
	return call<PayloadTest>('post', 'payload/test', { data: { input } })
}

/**
 * The parameters of an incident report request.
 *
 * @param request - Subject and period
 */
function incidentParams(request: IncidentRequest): Record<string, string | number> {
	const params: Record<string, string | number> = request.type === 'user' ? { user: request.value } : { address: request.value }
	if (request.since !== null) {
		params.since = request.since
	}
	if (request.until !== null) {
		params.until = request.until
	}
	return params
}

/**
 * Build an incident report to show on the page. Needs a recent password confirmation.
 *
 * @param request - Subject and period
 */
export function buildIncidentReport(request: IncidentRequest): Promise<IncidentReport> {
	return call<IncidentReport>('post', 'incidents/report', { data: incidentParams(request), confirm: true })
}

/**
 * The incident report as a document: the server answers with the file itself.
 * Needs a recent password confirmation, like building the report.
 *
 * @param request - Subject and period
 * @param output - JSON, or the printable HTML page
 */
export async function downloadIncidentReport(request: IncidentRequest, output: 'json' | 'html'): Promise<{ blob: Blob, filename: string }> {
	try {
		const response = await axios.post<Blob>(url('incidents/report/download'), { ...incidentParams(request), output }, { confirmPassword: PwdConfirmationMode.Lax, responseType: 'blob' })
		const disposition = String(response.headers['content-disposition'] ?? '')
		const match = disposition.match(/filename="?([^";]+)"?/)
		return { blob: response.data, filename: match?.[1] ?? 'incident-report.' + output }
	} catch (error) {
		// Errors arrive as a blob too; read the OCS message out of it.
		if (isAxiosError(error) && error.response?.data instanceof Blob) {
			let ocs: unknown
			try {
				ocs = JSON.parse(await error.response.data.text())?.ocs
			} catch {
				throw error
			}
			throw explained(error, ocs as OcsError | undefined)
		}
		throw error
	}
}

/**
 * Accounts whose name, display name or email address contains a text, for
 * the account picker. Uses the provisioning API, which administrators may use.
 *
 * @param search - What was typed
 * @param signal - Cancels the request
 */
export async function searchAccounts(search: string, signal?: AbortSignal): Promise<{ uid: string, displayName: string, email: string | null }[]> {
	const { data } = await axios.get<OCSResponse<{ users: Record<string, { id: string, displayname?: string, email?: string | null }> | [] }>>(generateOcsUrl('cloud/users/details'), { params: { search, limit: 10 }, signal })
	return Object.values(data.ocs.data.users ?? {}).map((user) => ({ uid: user.id, displayName: user.displayname || user.id, email: user.email ?? null }))
}

/**
 * @param refresh - Count the accounts again instead of using the counts of the last hour
 * @param signal - Cancels the request
 */
export function fetchConfirmation(refresh = false, signal?: AbortSignal): Promise<ConfirmationOverview> {
	return call<ConfirmationOverview>('get', 'confirmation', { params: refresh ? { refresh: 1 } : {}, signal })
}

/**
 * The logins that wait for an administrator, read live.
 *
 * @param signal - Cancels the request
 */
export function fetchWaitingLogins(signal?: AbortSignal): Promise<LoginApproval[]> {
	return call<LoginApproval[]>('get', 'confirmation/waiting', { signal })
}

/**
 * Set what happens to every login that nothing can confirm, for all reasons at once.
 *
 * @param preset - recommended, refuse or allow
 */
export function setConfirmationPreset(preset: ConfirmationPreset): Promise<ConfirmationPresetResult> {
	return call<ConfirmationPresetResult>('put', 'confirmation/preset', { data: { preset }, confirm: true })
}

/**
 * @param limit - At most this many
 * @param after - The account the previous page ended with; empty for the first page
 * @param admins - Only administrators
 * @param signal - Cancels the request
 */
export function fetchUnconfirmableAccounts(limit = 50, after = '', admins = false, signal?: AbortSignal): Promise<UnconfirmableAccount[]> {
	return call<UnconfirmableAccount[]>('get', 'confirmation/accounts', { params: { limit, after, admins: admins ? 1 : 0 }, signal })
}

/**
 * The accounts that wait to become administrators, oldest first.
 *
 * @param signal - Cancels the request
 */
export function fetchAdminGrants(signal?: AbortSignal): Promise<AdminGrantRequest[]> {
	return call<AdminGrantRequest[]>('get', 'approvals/admin-grants', { signal })
}

/**
 * Approve a request: for a login, the waiting login continues; for a new
 * administrator, the account joins the group. Needs the password.
 *
 * @param id - The request
 */
export function approveRequest(id: number): Promise<unknown> {
	return call<unknown>('post', `approvals/${id}/approve`, { data: {}, confirm: true })
}

/**
 * Reject a request: for a login, the waiting login ends; for a new
 * administrator, nothing changes. Refusing needs no password.
 *
 * @param id - The request
 */
export function rejectRequest(id: number): Promise<unknown> {
	return call<unknown>('post', `approvals/${id}/reject`)
}
