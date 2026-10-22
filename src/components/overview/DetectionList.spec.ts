/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection, DetectionList as List } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import DetectionList from './DetectionList.vue'
import { fetchDetections } from '../../services/api.ts'
import { detectionFilters } from '../../store.ts'
import { makeDetail } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDetections: vi.fn(),
}))

/**
 * @param id - The detection id
 * @param checkId - Its check
 */
function detection(id: number, checkId = 'credential_stuffing'): Detection {
	return { ...makeDetail().detection, id, checkId, lastSeenAt: 1_760_000_000 + id }
}

/**
 * A page of detections the test answers by hand.
 */
function later() {
	let answer!: (value: List) => void
	const promise = new Promise<List>((resolve) => {
		answer = resolve
	})
	return { promise, answer }
}

/**
 * @param wrapper - The list
 */
function ids(wrapper: ReturnType<typeof mount>): string[] {
	return wrapper.findAll('[id^="detection-"]').map((row) => row.attributes('id')!)
}

describe('DetectionList', () => {
	afterEach(() => {
		Object.assign(detectionFilters, { check: '', severity: '', user: '', address: '', mode: '' })
		vi.mocked(fetchDetections).mockReset()
	})

	test('a filter change while more rows load never adds the old rows', async () => {
		const more = later()
		vi.mocked(fetchDetections)
			.mockResolvedValueOnce({ detections: [detection(1)], hasMore: true })
			.mockReturnValueOnce(more.promise)
			.mockResolvedValueOnce({ detections: [detection(5, 'password_spraying')], hasMore: false })
		const wrapper = mount(DetectionList, { global: { stubs: { DetectionRow: { props: ['detection'], template: '<li :id="`detection-${detection.id}`" />' } } } })
		await flushPromises()
		await wrapper.findAll('button').find((b) => b.text() === 'Show more')!.trigger('click')

		detectionFilters.check = 'password_spraying'
		await flushPromises()
		more.answer({ detections: [detection(2)], hasMore: false })
		await flushPromises()
		expect(ids(wrapper)).toEqual(['detection-5'])
	})

	test('the answer for filters that were left is never shown', async () => {
		const old = later()
		vi.mocked(fetchDetections)
			.mockReturnValueOnce(old.promise)
			.mockResolvedValueOnce({ detections: [detection(5, 'password_spraying')], hasMore: false })
		const wrapper = mount(DetectionList, { global: { stubs: { DetectionRow: { props: ['detection'], template: '<li :id="`detection-${detection.id}`" />' } } } })
		detectionFilters.check = 'password_spraying'
		await flushPromises()
		old.answer({ detections: [detection(1)], hasMore: false })
		await flushPromises()
		expect(ids(wrapper)).toEqual(['detection-5'])
	})
})
