/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { KnownDevice, LoggedOutElsewhere, PersonalActivity, PersonalOverview, SecurityEvent, TrustedNetwork } from './types.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { ApiError, call, url, write } from '../services/api.ts'

export const fetchOverview = () => call<PersonalOverview>(axios.get(url('personal/overview')))

/**
 * The open questions and the timeline.
 *
 * @param limit - At most this many timeline entries, newest first
 * @param days - How far back
 */
export function fetchActivity(limit: number, days = 30): Promise<PersonalActivity> {
	return call<PersonalActivity>(axios.get(url('personal/activity'), { params: { days, limit } }))
}

/**
 * "No, it was not me". It needs no password: it can only lock someone out.
 *
 * @param id - The event
 */
export function denyEvent(id: number): Promise<SecurityEvent> {
	return call<SecurityEvent>(axios.post(url(`personal/detections/${id}/deny`)))
}

/**
 * "Yes, it was me", after a recent password confirmation.
 *
 * @param id - The event
 */
export function confirmEvent(id: number): Promise<SecurityEvent> {
	return call<SecurityEvent>(axios.post(url(`personal/detections/${id}/confirm`), {}, write))
}

/**
 * Whether the server refused "Yes, it was me" from this session.
 *
 * @param error - The error the answer threw
 */
export function isRefusedFromThisSession(error: unknown): boolean {
	return error instanceof ApiError && isAxiosError(error.cause) && error.cause.response?.status === 403
}

export const fetchKnownDevices = () => call<KnownDevice[]>(axios.get(url('personal/known-devices')))

/**
 * @param id - The device
 */
export function removeKnownDevice(id: number): Promise<{ removed: number }> {
	return call<{ removed: number }>(axios.delete(url(`personal/known-devices/${id}`)))
}

export const fetchTrustedNetworks = () => call<TrustedNetwork[]>(axios.get(url('personal/trusted-networks')))

/**
 * @param id - The entry
 */
export function removeTrustedNetwork(id: number): Promise<{ removed: number }> {
	return call<{ removed: number }>(axios.delete(url(`personal/trusted-networks/${id}`)))
}

export const logOutElsewhere = () => call<LoggedOutElsewhere>(axios.post(url('personal/log-out-elsewhere'), {}, write))
