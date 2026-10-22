/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Ref } from 'vue'
import type { ResourceOptions, UsedResource } from './useResource.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h, KeepAlive, nextTick, ref } from 'vue'
import { ApiError } from '../services/api.ts'
import { invalidate, resource, update, useResource } from './useResource.ts'

/**
 * A request the test answers by hand.
 */
function deferred<T>() {
	let resolve!: (value: T) => void
	let reject!: (error: unknown) => void
	const promise = new Promise<T>((res, rej) => {
		resolve = res
		reject = rej
	})
	return { promise, resolve, reject }
}

/**
 * Mount a component that shows a resource.
 *
 * @param key - The key
 * @param fetcher - Loads the data
 * @param options - Resource options
 */
function show<T>(key: string | Ref<string | null>, fetcher: (signal: AbortSignal) => Promise<T>, options: ResourceOptions = {}) {
	let used!: UsedResource<T>
	const wrapper = mount(defineComponent({
		setup() {
			used = useResource(key, fetcher, options)
			return () => h('div', String(used.data.value ?? ''))
		},
	}))
	return { wrapper, used }
}

describe('useResource', () => {
	test('two components that show one key share one request and one copy', async () => {
		const fetcher = vi.fn(async () => ['a'])
		const first = show('list', fetcher)
		const second = show('list', fetcher)
		await flushPromises()
		expect(fetcher).toHaveBeenCalledTimes(1)
		expect(second.used.data.value).toEqual(['a'])

		first.used.data.value = ['b']
		expect(second.used.data.value).toEqual(['b'])
	})

	test('data the page came with is not loaded again', async () => {
		const fetcher = vi.fn(async () => 'loaded')
		resource('level', fetcher, { initial: 'initial', keep: true })
		const { used } = show('level', fetcher)
		await flushPromises()
		expect(fetcher).not.toHaveBeenCalled()
		expect(used.data.value).toBe('initial')
	})

	test('an answer to an older request never replaces a newer one', async () => {
		const requests = [deferred<string>(), deferred<string>()]
		const key = ref<string | null>('rows:old')
		const { used } = show(key, vi.fn().mockReturnValueOnce(requests[0]!.promise).mockReturnValueOnce(requests[1]!.promise))
		await nextTick()
		used.reload()
		requests[1]!.resolve('new')
		await flushPromises()
		requests[0]!.resolve('old')
		await flushPromises()
		expect(used.data.value).toBe('new')
	})

	test('the late answer for a key that was left is not shown', async () => {
		const old = deferred<string>()
		const key = ref<string | null>('filter:a')
		const fetcher = vi.fn(() => key.value === 'filter:a' ? old.promise : Promise.resolve('b'))
		const { used } = show(key, fetcher)
		await nextTick()
		key.value = 'filter:b'
		await flushPromises()
		old.resolve('a')
		await flushPromises()
		expect(used.data.value).toBe('b')
	})

	test('a new request and an unmount cancel the request under way', async () => {
		const signals: AbortSignal[] = []
		const fetcher = vi.fn((signal: AbortSignal) => {
			signals.push(signal)
			return new Promise<string>(() => undefined)
		})
		const { wrapper, used } = show('slow', fetcher)
		await nextTick()
		used.reload()
		expect(signals[0]!.aborted).toBe(true)
		expect(signals[1]!.aborted).toBe(false)
		wrapper.unmount()
		expect(signals[1]!.aborted).toBe(true)
	})

	test('an invalidation loads what is shown again and drops the answer under way', async () => {
		const first = deferred<string>()
		const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValueOnce('after the change')
		const { used } = show('questions', fetcher)
		await nextTick()
		await invalidate('questions')
		first.resolve('before the change')
		await flushPromises()
		expect(used.data.value).toBe('after the change')
	})

	test('a name covers its keys: "detection" invalidates "detection:42"', async () => {
		const fetcher = vi.fn(async () => 'x')
		show('detection:42', fetcher)
		show('detections', fetcher)
		await flushPromises()
		fetcher.mockClear()
		await invalidate('detection')
		expect(fetcher).toHaveBeenCalledTimes(1)
	})

	test('a resource nothing shows is loaded when it is shown next, not at the invalidation', async () => {
		const fetcher = vi.fn(async () => 'x')
		resource('hidden', fetcher)
		await invalidate('hidden')
		expect(fetcher).not.toHaveBeenCalled()
		show('hidden', fetcher)
		await flushPromises()
		expect(fetcher).toHaveBeenCalledTimes(1)
	})

	test('a resource a store keeps loads again at the invalidation', async () => {
		const fetcher = vi.fn(async () => 'new')
		const kept = resource('status', fetcher, { initial: 'old', keep: true })
		await invalidate('status')
		expect(kept.data).toBe('new')
	})

	test('update changes the loaded data in place', async () => {
		const { used } = show('items', async () => [1, 2])
		await flushPromises()
		update<number[]>('items', (items) => {
			items.push(3)
		})
		update<number[]>('items', (items) => items.filter((item) => item !== 1))
		expect(used.data.value).toEqual([2, 3])
	})

	test('a failure keeps the data and gives the server\'s message or the fallback', async () => {
		const fetcher = vi.fn().mockResolvedValueOnce('data').mockRejectedValueOnce(new ApiError('Not allowed')).mockRejectedValueOnce(new Error('offline'))
		const { used } = show('failing', fetcher, { failure: () => 'Could not load' })
		await flushPromises()
		await used.reload()
		expect(used.data.value).toBe('data')
		expect(used.error.value).toBe('Not allowed')
		await used.reload()
		expect(used.error.value).toBe('Could not load')
	})

	describe('in KeepAlive', () => {
		beforeEach(() => {
			vi.useFakeTimers()
		})
		afterEach(() => {
			vi.useRealTimers()
		})

		test('loads once when mounted, and again when shown after it became stale', async () => {
			const fetcher = vi.fn(async () => 'x')
			const Inner = defineComponent({
				setup() {
					useResource('tab', fetcher, { staleAfter: 1000 })
					return () => h('div')
				},
			})
			const Other = defineComponent({ render: () => h('span') })
			const which = ref<'inner' | 'other'>('inner')
			mount(defineComponent({
				setup: () => () => h(KeepAlive, null, [which.value === 'inner' ? h(Inner) : h(Other)]),
			}))
			await flushPromises()
			expect(fetcher).toHaveBeenCalledTimes(1)

			which.value = 'other'
			await nextTick()
			which.value = 'inner'
			await flushPromises()
			expect(fetcher).toHaveBeenCalledTimes(1)

			which.value = 'other'
			await nextTick()
			vi.advanceTimersByTime(2000)
			await invalidate('tab')
			expect(fetcher).toHaveBeenCalledTimes(1)
			which.value = 'inner'
			await flushPromises()
			expect(fetcher).toHaveBeenCalledTimes(2)
		})
	})

	describe('polling', () => {
		beforeEach(() => {
			vi.useFakeTimers()
		})
		afterEach(() => {
			vi.useRealTimers()
			Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
		})

		test('pauses while the browser tab is hidden and catches up when it is visible', async () => {
			const fetcher = vi.fn(async () => 'x')
			show('waiting', fetcher, { poll: 1000 })
			await flushPromises()
			expect(fetcher).toHaveBeenCalledTimes(1)

			await vi.advanceTimersByTimeAsync(1000)
			expect(fetcher).toHaveBeenCalledTimes(2)

			Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
			await vi.advanceTimersByTimeAsync(5000)
			expect(fetcher).toHaveBeenCalledTimes(2)

			Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
			document.dispatchEvent(new Event('visibilitychange'))
			await flushPromises()
			expect(fetcher).toHaveBeenCalledTimes(3)
		})
	})
})
