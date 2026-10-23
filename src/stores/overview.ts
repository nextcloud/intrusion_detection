/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { MaybeRefOrGetter } from 'vue'
import type { ResourceOptions } from '../composables/useResource.ts'
import type { AccountGuide } from '../secureAccountTypes.ts'
import type { DetectionList } from '../types.ts'

import { toValue } from 'vue'
import { update, usePagedResource, useResource } from '../composables/useResource.ts'
import { fetchDailyStats, fetchDetection, fetchDetections, lookup } from '../services/api.ts'
import { confirmPasswordReset, endAccountSessions, fetchAccountGuide, reenableAccount } from '../services/secureAccount.ts'
import { detectionFilters } from '../store.ts'

/** Detections loaded first and added by each "Show more" */
const DETECTION_PAGE = 25
/** The incident list covers the detections of this many days */
const RECENT_DAYS = 7
/** At most this many recent detections are listed; the most the API returns */
const RECENT_LIMIT = 100

/**
 * The detections for the overview's filters, with "Show more".
 *
 * @param options - Resource options
 */
export function useDetectionList(options: ResourceOptions = {}) {
	return usePagedResource<DetectionList>(
		() => 'detections:' + JSON.stringify(detectionFilters),
		(list, signal) => fetchDetections({ ...detectionFilters }, DETECTION_PAGE, list?.detections.length ?? 0, 0, signal),
		(list, next) => ({ detections: [...list.detections, ...next.detections], hasMore: next.hasMore }),
		options,
	)
}

/**
 * The detections of the last days, for the list of the Incidents tab.
 *
 * @param options - Resource options
 */
export function useRecentDetections(options: ResourceOptions = {}) {
	return useResource('detections:recent', (signal) => fetchDetections({}, RECENT_LIMIT, 0, Math.floor(Date.now() / 1000) - RECENT_DAYS * 86400, signal), options)
}

/**
 * The narrative of a detection. A detection seen again is a new version.
 *
 * @param id - The detection, or null while it is not shown
 * @param seen - When it was last seen, if known
 * @param options - Resource options
 */
export function useDetection(id: MaybeRefOrGetter<string | null>, seen: MaybeRefOrGetter<number | undefined>, options: ResourceOptions = {}) {
	return useResource(() => {
		const detection = toValue(id)
		const version = toValue(seen)
		return detection === null ? null : `detection:${detection}` + (version === undefined ? '' : `:${version}`)
	}, (signal) => fetchDetection(toValue(id)!, signal), options)
}

/**
 * Detections per day, for the chart.
 *
 * @param options - Resource options
 */
export function useDailyStats(options: ResourceOptions = {}) {
	return useResource('stats', (signal) => fetchDailyStats(30, signal), options)
}

/**
 * What the lookup found for a reference, an address or an account.
 *
 * @param query - What was looked up, or null for nothing
 * @param options - Resource options
 */
export function useLookup(query: MaybeRefOrGetter<string | null>, options: ResourceOptions = {}) {
	return useResource(() => {
		const q = toValue(query)
		return q === null ? null : 'lookup:' + q
	}, (signal) => lookup(toValue(query)!, signal), options)
}

/**
 * The "Secure my account" state of the account of a detection.
 *
 * @param detectionId - A detection about the account
 * @param options - Resource options
 */
export function useAccountGuide(detectionId: MaybeRefOrGetter<string>, options: ResourceOptions = {}) {
	return useResource(() => 'account-guide:' + toValue(detectionId), (signal) => fetchAccountGuide(toValue(detectionId), signal), options)
}

/**
 * @param detectionId - The detection of the lock
 */
export async function reenableLockedAccount(detectionId: string): Promise<void> {
	const guide = await reenableAccount(detectionId)
	update<AccountGuide>('account-guide:' + detectionId, () => guide)
}

/**
 * Record that the account's new password was set by the administrator.
 *
 * @param detectionId - A detection about the account
 */
export async function confirmAccountPasswordReset(detectionId: string): Promise<void> {
	const guide = await confirmPasswordReset(detectionId)
	update<AccountGuide>('account-guide:' + detectionId, () => guide)
}

/**
 * Log the account of a detection out everywhere.
 *
 * @param detectionId - A detection about the account
 */
export async function logOutAccountEverywhere(detectionId: string): Promise<void> {
	await endAccountSessions(detectionId)
}
