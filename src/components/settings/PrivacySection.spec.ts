/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { GlobalSetting, Privacy } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import PrivacySection from './PrivacySection.vue'
import { fetchPrivacy } from '../../services/api.ts'
import { setAdvanced, state } from '../../store.ts'

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

	afterEach(() => {
		setAdvanced(false)
		window.localStorage.clear()
	})

	test('sums up what is kept, for how long, and what leaves the server', async () => {
		setAdvanced(false)
		const wrapper = await mountSection()
		const summary = wrapper.get('[data-test="privacy-summary"]').text()
		expect(summary).toContain('Detections are kept for 90 days.')
		expect(summary).toContain('kept for 180 days')
		expect(summary).toContain('Only these contact other services: Breached password check.')
		expect(wrapper.find('[data-test="stored-toggle"]').exists()).toBe(false)
		expect(wrapper.text()).not.toContain('Label of retention_detections_days')
		expect(wrapper.text()).not.toContain('A note on the GDPR')
	})

	test('the advanced options add the full table, the retention settings and the outgoing data', async () => {
		setAdvanced(true)
		const wrapper = await mountSection()
		expect(wrapper.find('[data-test="stored-toggle"]').exists()).toBe(true)
		expect(wrapper.text()).toContain('Label of retention_detections_days')
		expect(wrapper.text()).toContain('What leaves the server')
		expect(wrapper.text()).toContain('5 characters of a hash')
		expect(wrapper.text()).toContain('A note on the GDPR')
	})
})
