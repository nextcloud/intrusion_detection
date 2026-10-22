/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { MaybeRefOrGetter } from 'vue'
import type { ResourceOptions } from '../composables/useResource.ts'
import type { BanList, Blocklist, Blocklists, DecoyFormat, NewDecoy, SyncResult, Traps } from '../types.ts'

import { toValue } from 'vue'
import { invalidate, update, usePagedResource, useResource } from '../composables/useResource.ts'
import {
	createBlocklist,
	createDecoy,
	deleteDecoy,
	fetchBans,
	fetchBlocklists,
	fetchExport,
	fetchTraps,
	removeBlocklist,
	syncBlocklist,
	updateBlocklist,
	updateReservedNames,
	updateTrapPaths,
} from '../services/api.ts'

/** Blocks loaded first and added by each "Show more" */
const BAN_PAGE = 50

/**
 * The blocks, with "Show more".
 *
 * @param all - Also the ended and lifted ones
 * @param options - Resource options
 */
export function useBanList(all: MaybeRefOrGetter<boolean>, options: ResourceOptions = {}) {
	return usePagedResource<BanList>(
		() => toValue(all) ? 'bans:all' : 'bans:active',
		(list, signal) => fetchBans(toValue(all), BAN_PAGE, list?.bans.length ?? 0, signal),
		(list, next) => ({ ...list, bans: [...list.bans, ...next.bans], hasMore: next.hasMore }),
		options,
	)
}

/**
 * The blocklists and network lists.
 *
 * @param options - Resource options
 */
export function useBlocklists(options: ResourceOptions = {}) {
	return useResource('blocklists', fetchBlocklists, options)
}

/**
 * @param list - A list as the server returned it
 */
function putBlocklist(list: Blocklist): void {
	update<Blocklists>('blocklists', (data) => {
		const index = data.lists.findIndex((l) => l.id === list.id)
		if (index === -1) {
			data.lists.push(list)
		} else {
			data.lists.splice(index, 1, list)
		}
	})
}

/**
 * @param list - The new list
 * @param list.id - Its short name
 * @param list.url - Where to download it
 * @param list.purpose - Block, or mark as hosting or Tor
 * @param list.format - The file format
 * @param list.mode - For blocklists: observe or protect
 */
export async function addBlocklist(list: { id: string, url: string, purpose: string, format: string, mode: string }): Promise<Blocklist> {
	const created = await createBlocklist(list)
	putBlocklist(created)
	return created
}

/**
 * @param id - The list
 * @param change - What to change
 * @param change.enabled - Use the list
 * @param change.mode - Observe or protect
 * @param change.interval - Seconds between downloads, 0 for the default
 */
export async function changeBlocklist(id: string, change: { enabled?: boolean, mode?: string, interval?: number }): Promise<void> {
	putBlocklist(await updateBlocklist(id, change))
}

/**
 * Download a list now.
 *
 * @param id - The list
 */
export async function syncBlocklistNow(id: string): Promise<SyncResult> {
	const { result, list } = await syncBlocklist(id)
	putBlocklist(list)
	return result
}

/**
 * @param id - The custom list to remove
 */
export async function deleteBlocklist(id: string): Promise<void> {
	await removeBlocklist(id)
	update<Blocklists>('blocklists', (data) => {
		data.lists = data.lists.filter((l) => l.id !== id)
	})
}

/**
 * The decoys, the reserved names and the trap paths.
 *
 * @param options - Resource options
 */
export function useTraps(options: ResourceOptions = {}) {
	return useResource('traps', fetchTraps, options)
}

/**
 * @param decoy - The decoy to create
 * @param decoy.label - Where it is planted
 * @param decoy.loginName - An optional login name no account uses
 * @param decoy.format - What the secret looks like
 */
export async function addDecoy(decoy: { label: string, loginName: string, format: DecoyFormat }): Promise<NewDecoy> {
	const created = await createDecoy(decoy)
	update<Traps>('traps', (traps) => {
		traps.decoys = [created.decoy, ...traps.decoys]
	})
	return created
}

/**
 * @param id - The decoy
 */
export async function removeDecoy(id: number): Promise<void> {
	await deleteDecoy(id)
	update<Traps>('traps', (traps) => {
		traps.decoys = traps.decoys.filter((d) => d.id !== id)
	})
}

/**
 * The reserved names are a setting of their check.
 *
 * @param change - Names to reserve and to release
 * @param change.add - Names to reserve
 * @param change.remove - Names to release
 */
export async function changeReservedNames(change: { add?: string[], remove?: string[] }): Promise<void> {
	const reserved = await updateReservedNames(change)
	update<Traps>('traps', (traps) => {
		traps.reservedNames = reserved
	})
	await invalidate('checks')
}

/**
 * The trap paths are settings of their check.
 *
 * @param change - What to change
 * @param change.add - Paths to add
 * @param change.remove - Paths to remove
 * @param change.builtinEnabled - Use the built-in list
 * @param change.autodiscover - Trap the autodiscover path
 */
export async function changeTrapPaths(change: { add?: string[], remove?: string[], builtinEnabled?: boolean, autodiscover?: boolean }): Promise<void> {
	const paths = await updateTrapPaths(change)
	update<Traps>('traps', (traps) => {
		traps.trapPaths = paths
	})
	await invalidate('checks')
}

/**
 * Where the firewall export writes, and the snippets to read it.
 *
 * @param options - Resource options
 */
export function useFirewallExport(options: ResourceOptions = {}) {
	return useResource('firewall-export', fetchExport, options)
}
