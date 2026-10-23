/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { MaybeRefOrGetter, Ref, WritableComputedRef } from 'vue'

import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, reactive, shallowRef, toValue, watch } from 'vue'
import { errorMessage } from '../services/api.ts'
import { logger } from '../services/logger.ts'

/**
 * Data loaded from the server, shared by key: every component that asks for
 * one key gets the same copy and the same request.
 *
 * A resource is loaded when a component that shows it is mounted, and again
 * when such a component is shown again (in `<KeepAlive>`) after the data
 * became older than `staleAfter`. `invalidate()` marks resources out of date
 * after a change: those on screen, and those a store keeps, load again at
 * once; the others when they are shown next. Only the answer to the latest
 * request is taken, and a request nobody waits for any more is cancelled.
 */
export interface Resource<T> {
	readonly key: string
	data: T | null
	/** What the last load threw, until a load works */
	error: unknown
	loading: boolean
}

interface Entry<T> {
	state: Resource<T>
	fetcher: (signal: AbortSignal) => Promise<T>
	/** When the data was loaded; 0 when it is out of date */
	fetchedAt: number
	/** Counts the requests; only the latest one may set the data */
	sequence: number
	pending: Promise<void> | null
	controller: AbortController | null
	/** Mounted components that use it */
	users: number
	/** Of those, the ones on screen (not deactivated in `<KeepAlive>`) */
	shown: number
	/** A store keeps it: it stays when no component uses it, and reloads on invalidation */
	kept: boolean
}

/** Data older than this is loaded again when a component shows it again */
const STALE_AFTER = 30_000

const entries = new Map<string, Entry<unknown>>()

/**
 * The resource of a key, created on first use.
 *
 * @param key - The key, e.g. "bans" or "detection:42"
 * @param fetcher - Loads the data; the latest one given is used
 * @param options - How it starts
 * @param options.initial - Data the page came with; counts as just loaded
 * @param options.keep - The store keeps it, also while nothing shows it
 */
export function resource<T>(key: string, fetcher: (signal: AbortSignal) => Promise<T>, options: { initial?: T | null, keep?: boolean } = {}): Resource<T> {
	return entry(key, fetcher, options).state
}

/**
 * @param key - The key
 * @param fetcher - Loads the data
 * @param options - See `resource()`
 * @param options.initial - Data the page came with
 * @param options.keep - The store keeps it
 */
function entry<T>(key: string, fetcher: (signal: AbortSignal) => Promise<T>, options: { initial?: T | null, keep?: boolean } = {}): Entry<T> {
	let found = entries.get(key) as Entry<T> | undefined
	if (found === undefined) {
		const initial = options.initial ?? null
		found = {
			state: reactive({ key, data: initial, error: null, loading: false }) as Resource<T>,
			fetcher,
			fetchedAt: initial === null ? 0 : Date.now(),
			sequence: 0,
			pending: null,
			controller: null,
			users: 0,
			shown: 0,
			kept: options.keep ?? false,
		}
		entries.set(key, found as Entry<unknown>)
	}
	found.fetcher = fetcher
	found.kept ||= options.keep ?? false
	return found
}

/**
 * Load a resource. A request that is under way is shared, unless `fresh`
 * asks for a new one, which cancels it.
 *
 * @param target - The resource
 * @param fresh - Start a new request even when one is under way
 */
function load<T>(target: Entry<T>, fresh = false): Promise<void> {
	if (target.pending !== null && !fresh) {
		return target.pending
	}
	target.controller?.abort()
	const controller = new AbortController()
	const sequence = ++target.sequence
	target.controller = controller
	target.state.loading = true
	const request = (async () => {
		try {
			const data = await target.fetcher(controller.signal)
			if (sequence === target.sequence) {
				target.state.data = data
				target.state.error = null
				target.fetchedAt = Date.now()
			}
		} catch (error) {
			if (sequence === target.sequence && !controller.signal.aborted) {
				logger.error(`Could not load ${target.state.key}`, { error })
				target.state.error = error
			}
		} finally {
			if (sequence === target.sequence) {
				target.state.loading = false
				target.pending = null
				target.controller = null
			}
		}
	})()
	target.pending = request
	return request
}

/**
 * Whether a key belongs to a name: "bans" covers "bans" and "bans:all".
 *
 * @param key - The key of a resource
 * @param name - What was invalidated
 */
function covers(key: string, name: string): boolean {
	return key === name || key.startsWith(name + ':')
}

/**
 * Mark resources out of date after a change. Those on screen and those a
 * store keeps load again at once; the answers of requests that were under
 * way are dropped. Resolves when the new data is in.
 *
 * @param names - Keys, or names that cover keys: "detection" covers "detection:42"
 */
export function invalidate(...names: string[]): Promise<void> {
	const reloads: Promise<void>[] = []
	for (const target of entries.values()) {
		if (!names.some((name) => covers(target.state.key, name))) {
			continue
		}
		target.fetchedAt = 0
		if (target.kept || target.shown > 0) {
			reloads.push(load(target, true))
		} else if (target.pending !== null) {
			target.controller?.abort()
			target.sequence++
			target.pending = null
			target.controller = null
			target.state.loading = false
		}
	}
	return Promise.all(reloads).then(() => undefined)
}

/**
 * Change the loaded data of a resource in place, e.g. with an item a write
 * returned. Nothing happens while it is not loaded.
 *
 * @param key - The key
 * @param change - Gets the data and changes it, or returns the new data
 */
export function update<T>(key: string, change: (data: T) => T | void): void {
	const target = entries.get(key) as Entry<T> | undefined
	if (target?.state.data !== null && target?.state.data !== undefined) {
		const result = change(target.state.data)
		if (result !== undefined) {
			target.state.data = result
		}
	}
}

/**
 * Forget what components loaded and cancel every request. The resources a
 * store keeps stay, with their data, but count as out of date. For tests,
 * which start each case afresh.
 */
export function clearResources(): void {
	for (const [key, target] of entries) {
		target.controller?.abort()
		Object.assign(target, { fetchedAt: 0, sequence: target.sequence + 1, pending: null, controller: null, users: 0, shown: 0 })
		target.state.loading = false
		if (!target.kept) {
			entries.delete(key)
		}
	}
}

export interface ResourceOptions {
	/** Load again this often (ms) while it is shown and the browser tab is visible */
	poll?: number
	/** Shown again after this long (ms), it is loaded again */
	staleAfter?: number
	/** What to say when it could not be loaded and the server did not explain why; empty without */
	failure?: () => string
}

export interface UsedResource<T> {
	/** The data; null until loaded. Writing it changes the shared copy */
	data: WritableComputedRef<T | null>
	/** What to show when the last load failed */
	error: Ref<string | null>
	loading: Ref<boolean>
	/** Load it now, even when it is fresh */
	reload: () => Promise<void>
}

/**
 * Show a resource in a component: it is loaded on mount, and again when it
 * is shown after `staleAfter` or after an invalidation. A key of null shows
 * nothing and loads nothing; a new key switches to that resource.
 *
 * @param key - The key, or null for nothing
 * @param fetcher - Loads the data
 * @param options - Polling, freshness and the failure text
 */
export function useResource<T>(key: MaybeRefOrGetter<string | null>, fetcher: (signal: AbortSignal) => Promise<T>, options: ResourceOptions = {}): UsedResource<T> {
	const staleAfter = options.staleAfter ?? STALE_AFTER
	const find = (name: string | null) => name === null ? null : entry(name, fetcher)
	// Data loaded before is there for the first render.
	const current = shallowRef<Entry<T> | null>(find(toValue(key)))
	let mounted = false
	let shown = false

	/**
	 * Load the resource when it is older than allowed.
	 *
	 * @param maxAge - How old it may be
	 */
	function refresh(maxAge = staleAfter): void {
		const target = current.value
		if (target !== null && (target.fetchedAt === 0 || Date.now() - target.fetchedAt > maxAge)) {
			void load(target)
		}
	}

	/**
	 * @param target - The resource to stop using
	 */
	function release(target: Entry<T>): void {
		target.users--
		if (shown) {
			target.shown--
		}
		if (target.users === 0 && !target.kept) {
			target.controller?.abort()
			entries.delete(target.state.key)
		}
	}

	/**
	 * @param target - The resource to use
	 */
	function attach(target: Entry<T>): void {
		target.users++
		if (shown) {
			target.shown++
		}
	}

	watch(() => toValue(key), (next) => {
		const previous = current.value
		current.value = find(next)
		if (mounted) {
			if (previous !== null) {
				release(previous)
			}
			if (current.value !== null) {
				attach(current.value)
				refresh()
			}
		}
	})

	/**
	 * The component is on screen.
	 */
	function show(): void {
		if (shown) {
			return
		}
		shown = true
		if (current.value !== null) {
			current.value.shown++
		}
		refresh()
	}

	/**
	 * The component left the screen.
	 */
	function hide(): void {
		if (!shown) {
			return
		}
		shown = false
		if (current.value !== null) {
			current.value.shown--
		}
	}

	let timer: ReturnType<typeof setInterval> | undefined
	const poll = options.poll
	/**
	 * Load again when the browser tab becomes visible and a poll was missed.
	 */
	function onVisibility(): void {
		if (poll !== undefined && shown && document.visibilityState !== 'hidden') {
			refresh(poll)
		}
	}

	onMounted(() => {
		mounted = true
		current.value = find(toValue(key))
		if (current.value !== null) {
			attach(current.value)
		}
		show()
		if (poll !== undefined) {
			timer = setInterval(() => {
				if (shown && document.visibilityState !== 'hidden' && current.value !== null) {
					void load(current.value)
				}
			}, poll)
			document.addEventListener('visibilitychange', onVisibility)
		}
	})
	onActivated(show)
	onDeactivated(hide)
	onBeforeUnmount(() => {
		clearInterval(timer)
		document.removeEventListener('visibilitychange', onVisibility)
		hide()
		if (current.value !== null) {
			release(current.value)
		}
		mounted = false
	})

	const failure = options.failure ?? (() => '')
	return {
		data: computed({
			get: () => current.value?.state.data ?? null,
			set: (value) => {
				if (current.value !== null) {
					current.value.state.data = value
				}
			},
		}),
		error: computed(() => current.value?.state.error ? errorMessage(current.value.state.error, failure()) : null),
		loading: computed(() => current.value?.state.loading ?? false),
		reload: () => current.value === null ? Promise.resolve() : load(current.value, true),
	}
}

/**
 * A list with "Show more": the first page is a resource, and `loadMore`
 * adds the next page to it. A page that arrives after the list was loaded
 * anew, e.g. for other filters, is dropped.
 *
 * @param key - The key of the first page
 * @param page - Loads the first page (for null), or the page after a list
 * @param append - The list with the next page added
 * @param options - Resource options
 */
export function usePagedResource<T>(
	key: MaybeRefOrGetter<string | null>,
	page: (list: T | null, signal: AbortSignal) => Promise<T>,
	append: (list: T, next: T) => T,
	options: ResourceOptions = {},
): UsedResource<T> & { loadMore: () => Promise<void> } {
	const list = useResource(key, (signal) => page(null, signal), options)
	let controller: AbortController | null = null
	watch(list.data, () => controller?.abort())
	onBeforeUnmount(() => controller?.abort())

	/**
	 * Add the next page; throws when it could not be loaded.
	 */
	async function loadMore(): Promise<void> {
		const current = list.data.value
		if (current === null) {
			return
		}
		controller?.abort()
		controller = new AbortController()
		const { signal } = controller
		try {
			const next = await page(current, signal)
			if (list.data.value === current) {
				list.data.value = append(current, next)
			}
		} catch (error) {
			if (!signal.aborted) {
				throw error
			}
		}
	}

	return { ...list, loadMore }
}
