/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting, Privacy } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import PrivacySection from './PrivacySection.vue'
import { fetchPrivacy } from '../../services/api.ts'
import { state } from '../../store.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchPrivacy: vi.fn(),
}))

/**
 * @param name - The setting
 * @param value - Its value in days
 */
function days(name: string, value: number): GlobalSetting {
	return { name, type: 'int', default: value, min: 1, max: 3650, choices: [], value, label: `Label of ${name}`, help: '', unit: 'days', group: 'privacy' }
}

const privacy: Privacy = {
	stored: [{ id: 'detections', name: 'Detections', what: 'What happened', why: 'To explain it', retention: '{retention_detections_days} days', where: 'ids_detections', checks: [] }],
	outgoing: [
		{ id: 'breach', name: 'Breached password check', text: 'Sends a hash prefix.', active: true, items: ['5 characters of a hash'] },
		{ id: 'lists', name: 'Blocklists', text: 'Downloads lists.', active: false, items: [] },
	],
	gdpr: ['Security logs are a legitimate interest.'],
}

/**
 * Mount the section once the overview is loaded.
 */
async function mountSection() {
	vi.mocked(fetchPrivacy).mockResolvedValue(privacy)
	const wrapper = mount(PrivacySection)
	await flushPromises()
	return wrapper
}

describe('the data and privacy section', () => {
	beforeEach(() => {
		state.settings = [days('retention_detections_days', 90), days('history_retention_days', 180)]
	})

	test('one card says what is kept and for how long, the next one what leaves the server', async () => {
		const wrapper = await mountSection()
		const kept = wrapper.get('[data-test="privacy-kept"]')
		expect(kept.get('[data-test="privacy-retention"]').text()).toContain('Detections are kept for 90 days.')
		expect(kept.text()).toContain('kept for 180 days')
		expect(kept.find('[data-test="stored-toggle"]').exists()).toBe(true)
		expect(wrapper.text()).not.toContain('What Nextcloud stores')
		expect(wrapper.get('[data-test="privacy-outgoing"]').text()).toBe('Only these contact other services: Breached password check.')
	})

	test('then the retention settings, the outgoing data, and the full table behind its toggle', async () => {
		const wrapper = await mountSection()
		expect(wrapper.get('[data-test="stored-toggle"] button').attributes('aria-expanded')).toBe('false')
		expect(wrapper.find('[data-test="stored-data"]').exists()).toBe(false)
		expect(wrapper.text()).toContain('Label of retention_detections_days')
		expect(wrapper.text()).toContain('What leaves the server')
		expect(wrapper.text()).toContain('5 characters of a hash')
		expect(wrapper.text()).toContain('A note on the GDPR')
	})
})
