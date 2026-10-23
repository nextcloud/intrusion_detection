/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { KnownDevice, LoggedOutElsewhere, PersonalActivity, PersonalOverview, SecurityEvent, StaleCredential, TrustedNetwork } from './types.ts'

import { ApiError, call } from '../services/api.ts'

/**
 * @param signal - Cancels the request
 */
export function fetchOverview(signal?: AbortSignal): Promise<PersonalOverview> {
	return call<PersonalOverview>('get', 'personal/overview', { signal })
}

/**
 * The open questions and the timeline.
 *
 * @param limit - At most this many timeline entries, newest first
 * @param days - How far back
 * @param signal - Cancels the request
 */
export function fetchActivity(limit: number, days = 30, signal?: AbortSignal): Promise<PersonalActivity> {
	return call<PersonalActivity>('get', 'personal/activity', { params: { days, limit }, signal })
}

/**
 * "No, it was not me". It needs no password: it can only lock someone out.
 *
 * @param id - The event
 */
export function denyEvent(id: number): Promise<SecurityEvent> {
	return call<SecurityEvent>('post', `personal/detections/${id}/deny`)
}

/**
 * "Yes, it was me", after a recent password confirmation.
 *
 * @param id - The event
 */
export function confirmEvent(id: number): Promise<SecurityEvent> {
	return call<SecurityEvent>('post', `personal/detections/${id}/confirm`, { data: {}, confirm: true })
}

/**
 * Whether the server refused "Yes, it was me" from this session.
 *
 * @param error - The error the answer threw
 */
export function isRefusedFromThisSession(error: unknown): boolean {
	return error instanceof ApiError && error.reason === 'session_not_allowed'
}

/**
 * @param signal - Cancels the request
 */
export function fetchKnownDevices(signal?: AbortSignal): Promise<KnownDevice[]> {
	return call<KnownDevice[]>('get', 'personal/known-devices', { signal })
}

/**
 * @param id - The device
 */
export function removeKnownDevice(id: number): Promise<{ removed: number }> {
	return call<{ removed: number }>('delete', `personal/known-devices/${id}`)
}

/**
 * @param signal - Cancels the request
 */
export function fetchTrustedNetworks(signal?: AbortSignal): Promise<TrustedNetwork[]> {
	return call<TrustedNetwork[]>('get', 'personal/trusted-networks', { signal })
}

/**
 * @param id - The entry
 */
export function removeTrustedNetwork(id: number): Promise<{ removed: number }> {
	return call<{ removed: number }>('delete', `personal/trusted-networks/${id}`)
}

export const logOutElsewhere = () => call<LoggedOutElsewhere>('post', 'personal/log-out-elsewhere', { data: {}, confirm: true })

/**
 * @param signal - Cancels the request
 */
export function fetchStaleCredentials(signal?: AbortSignal): Promise<StaleCredential[]> {
	return call<StaleCredential[]>('get', 'personal/stale-credentials', { signal })
}

/**
 * Remove one unused app password or device, after a recent password confirmation.
 *
 * @param id - The credential
 */
export function removeStaleCredential(id: number): Promise<{ removed: number }> {
	return call<{ removed: number }>('delete', `personal/stale-credentials/${id}`, { confirm: true })
}

/**
 * Remove every unused app password and device, after a recent password confirmation.
 */
export const removeAllStaleCredentials = () => call<{ removed: number }>('delete', 'personal/stale-credentials', { confirm: true })
