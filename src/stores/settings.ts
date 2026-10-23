/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { MaybeRefOrGetter } from 'vue'
import type { ResourceOptions } from '../composables/useResource.ts'
import type { ConfirmationOverview, ConfirmationPreset, UnconfirmableAccount } from '../types.ts'

import { toValue } from 'vue'
import { invalidate, update, usePagedResource, useResource } from '../composables/useResource.ts'
import {
	fetchConfirmation,
	fetchDigest,
	fetchNotifications,
	fetchPrivacy,
	fetchSignatures,
	fetchUnconfirmableAccounts,
	fetchWebhookEvents,
	setConfirmationPreset,
	simulateCheck,
} from '../services/api.ts'

/**
 * The login confirmation overview. Each load counts the accounts again.
 *
 * @param options - Resource options
 */
export function useConfirmation(options: ResourceOptions = {}) {
	return useResource('confirmation', (signal) => fetchConfirmation(true, signal), options)
}

/**
 * Set what happens to every login that nothing can confirm.
 *
 * @param preset - The choice
 */
export async function chooseConfirmationPreset(preset: ConfirmationPreset): Promise<void> {
	const result = await setConfirmationPreset(preset)
	update<ConfirmationOverview>('confirmation', (overview) => {
		overview.preset = result.preset
		overview.policies = result.policies
	})
	await invalidate('settings')
}

/** Accounts that cannot confirm a login, loaded first and added by each "Show more" */
const ACCOUNT_PAGE = 50
/** The download asks for this many at a time */
const DOWNLOAD_PAGE = 200

/**
 * The accounts that cannot confirm a login, with "Show more".
 *
 * @param shown - Whether the list is shown; it loads only then
 * @param admins - Only administrators
 * @param options - Resource options
 */
export function useUnconfirmableAccounts(shown: MaybeRefOrGetter<boolean>, admins: MaybeRefOrGetter<boolean>, options: ResourceOptions = {}) {
	return usePagedResource<{ accounts: UnconfirmableAccount[], exhausted: boolean }>(
		() => toValue(shown) ? 'unconfirmable:' + (toValue(admins) ? 'admins' : 'all') : null,
		async (list, signal) => {
			const accounts = await fetchUnconfirmableAccounts(ACCOUNT_PAGE, list?.accounts.at(-1)?.uid ?? '', toValue(admins), signal)
			return { accounts, exhausted: accounts.length < ACCOUNT_PAGE }
		},
		(list, next) => ({ accounts: [...list.accounts, ...next.accounts], exhausted: next.exhausted }),
		{ staleAfter: 0, ...options },
	)
}

/**
 * Every account that cannot confirm a login, up to a limit, for the download.
 *
 * @param admins - Only administrators
 * @param max - At most this many
 */
export async function allUnconfirmableAccounts(admins: boolean, max: number): Promise<UnconfirmableAccount[]> {
	const rows: UnconfirmableAccount[] = []
	while (rows.length < max) {
		const page = await fetchUnconfirmableAccounts(DOWNLOAD_PAGE, rows.at(-1)?.uid ?? '', admins)
		rows.push(...page)
		if (page.length < DOWNLOAD_PAGE) {
			break
		}
	}
	return rows
}

/**
 * Who is notified of each check.
 *
 * @param options - Resource options
 */
export function useNotifications(options: ResourceOptions = {}) {
	return useResource('notifications', fetchNotifications, options)
}

/**
 * Who gets the digest and when.
 *
 * @param options - Resource options
 */
export function useDigest(options: ResourceOptions = {}) {
	return useResource('digest', fetchDigest, options)
}

/**
 * The events for webhooks, with example payloads.
 *
 * @param options - Resource options
 */
export function useWebhookEvents(options: ResourceOptions = {}) {
	return useResource('webhook-events', fetchWebhookEvents, options)
}

/**
 * What the app stores and sends, and for how long.
 *
 * @param options - Resource options
 */
export function usePrivacy(options: ResourceOptions = {}) {
	return useResource('privacy', fetchPrivacy, options)
}

/**
 * The signatures of the injection probe check.
 *
 * @param options - Resource options
 */
export function useSignatures(options: ResourceOptions = {}) {
	return useResource('signatures', fetchSignatures, options)
}

/**
 * What a check would report for a synthetic attack; run anew each time it is shown.
 *
 * @param checkId - The check, or null while nothing is simulated
 * @param options - Resource options
 */
export function useSimulation(checkId: MaybeRefOrGetter<string | null>, options: ResourceOptions = {}) {
	return useResource(() => {
		const id = toValue(checkId)
		return id === null ? null : 'simulation:' + id
	}, (signal) => simulateCheck(toValue(checkId)!, signal), { staleAfter: 0, ...options })
}
