/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Detection } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import DetectionGroup from './DetectionGroup.vue'
import { makeDetail } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchDetection: vi.fn(() => new Promise(() => {})),
}))

const detections: Detection[] = [17, 16, 15].map((id) => ({ ...makeDetail().detection, id, checkName: 'Admin change alerts', summary: `Security setting changed: setting ${id}. The administrators were notified.`, ip: null, uid: null, enforced: false, createdAt: 1000 + id, lastSeenAt: 1000 + id }))

describe('a group of detections', () => {
	test('reads "3 × Admin change alerts" and opens to its detections', async () => {
		const wrapper = mount(DetectionGroup, { props: { detections } })
		const button = wrapper.get('button')
		expect(button.text()).toContain('3 × Admin change alerts')
		expect(button.text()).toContain('within a minute')
		expect(button.text()).toContain('Observed')
		expect(button.attributes('aria-expanded')).toBe('false')
		expect(wrapper.findAll('[id^="detection-"]')).toHaveLength(0)
		await button.trigger('click')
		expect(button.attributes('aria-expanded')).toBe('true')
		expect(wrapper.findAll('[id^="detection-"]').map((row) => row.attributes('id'))).toEqual(['detection-17', 'detection-16', 'detection-15'])
	})

	test('opens by itself when a link points to one of its detections', () => {
		const wrapper = mount(DetectionGroup, { props: { detections, openId: 16 } })
		expect(wrapper.get('button').attributes('aria-expanded')).toBe('true')
		expect(wrapper.find('#detection-16').exists()).toBe(true)
	})

	test('a group whose detections read the same is named by their sentence', () => {
		const same = detections.map((d) => ({ ...d, summary: 'Trap URLs from 203.0.113.9. The address was blocked.' }))
		const wrapper = mount(DetectionGroup, { props: { detections: same } })
		expect(wrapper.get('[data-test="detection-summary"]').text()).toBe('Trap URLs from 203.0.113.9. The address was blocked.')
	})
})
