/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import CheckCard from './CheckCard.vue'
import { state } from '../../store.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateCheck: vi.fn(),
	resetCheck: vi.fn(),
	fetchStatus: vi.fn(() => new Promise(() => {})),
}))

describe('BreachedPasswordPrivacy', () => {
	beforeEach(() => {
		state.settings = []
		state.checks = []
	})

	afterEach(() => {
		document.body.innerHTML = ''
	})

	test('the breached password card links to the k-anonymity explanation', async () => {
		const check = makeCheck({ id: 'breached_password', sendsData: true, params: [], responses: [] })
		const card = mount(CheckCard, { props: { check, open: true }, attachTo: document.body })
		await flushPromises()
		await vi.dynamicImportSettled()
		await flushPromises()
		const link = card.get('[data-test="breach-privacy"] a')
		expect(link.attributes('href')).toBe('https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange')
		expect(link.attributes('target')).toBe('_blank')
		expect(link.attributes('rel')).toContain('noopener')
		expect(card.text()).toContain('This check contacts an external service.')
		card.unmount()
	})

	test('other checks do not show it', async () => {
		const card = mount(CheckCard, { props: { check: makeCheck(), open: true }, attachTo: document.body })
		await flushPromises()
		await vi.dynamicImportSettled()
		await flushPromises()
		expect(card.find('[data-test="breach-privacy"]').exists()).toBe(false)
		card.unmount()
	})
})
