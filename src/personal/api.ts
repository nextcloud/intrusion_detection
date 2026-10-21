/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { KnownDevice, LoggedOutElsewhere, Login, PersonalOverview, SecurityEvent, TrustedNetwork } from './types.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { ApiError, call, url, write } from '../services/api.ts'

export const fetchOverview = () => call<PersonalOverview>(axios.get(url('personal/overview')))

/**
 * @param limit - At most this many, newest first
 */
export function fetchEvents(limit = 100): Promise<SecurityEvent[]> {
	return call<SecurityEvent[]>(axios.get(url('personal/detections'), { params: { limit } }))
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

/**
 * @param days - How far back
 * @param limit - At most this many, newest first
 */
export function fetchLogins(days = 30, limit = 200): Promise<Login[]> {
	return call<Login[]>(axios.get(url('personal/logins'), { params: { days, limit } }))
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
