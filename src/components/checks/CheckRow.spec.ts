/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import CheckRow from './CheckRow.vue'
import { ApiError, updateCheck } from '../../services/api.ts'
import { state } from '../../store.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateCheck: vi.fn(),
	fetchStatus: vi.fn(() => new Promise(() => {})),
}))

const mounted: { unmount: () => void }[] = []

/**
 * @param check - The check
 * @param open - Open "Customise"
 */
function mountRow(check = makeCheck(), open = false) {
	const row = mount(CheckRow, { props: { check, open }, attachTo: document.body })
	mounted.push(row)
	return row
}

describe('a check on the Protection tab', () => {
	beforeEach(() => {
		state.checks = [makeCheck()]
		state.settings = []
	})

	afterEach(() => {
		mounted.splice(0).forEach((row) => row.unmount())
		vi.mocked(updateCheck).mockReset()
		document.body.innerHTML = ''
	})

	test('one row: name, what it does, the mode and how often it fired in 7 days', () => {
		const row = mountRow()
		expect(row.get('h4').text()).toBe('Credential stuffing')
		expect(row.text()).toContain('Many different login names failing from one source.')
		expect(row.get('[data-test="check-fired"]').text()).toBe('Fired 3 times in the last 7 days')
		expect(row.findAll('input[type="radio"]')).toHaveLength(3)
	})

	test('a quiet check says so', () => {
		const row = mountRow(makeCheck({ stats: { days: 7, detections: 0, enforced: 0, observed: 0, addressesBlocked: 0 } }))
		expect(row.get('[data-test="check-fired"]').text()).toBe('Quiet in the last 7 days')
	})

	test('the mode is saved at once', async () => {
		vi.mocked(updateCheck).mockResolvedValue(makeCheck({ mode: { configured: 'observe', effective: 'observe', reason: null, missing: null, default: 'protect' } }))
		const row = mountRow()
		const radios = row.findAll('input[type="radio"]')
		await radios[1]!.setValue(true)
		await radios[1]!.trigger('change')
		await flushPromises()
		expect(updateCheck).toHaveBeenCalledTimes(1)
		expect(updateCheck).toHaveBeenCalledWith('credential_stuffing', { mode: 'observe' })
	})

	test('a failed mode change goes back to the saved mode', async () => {
		vi.mocked(updateCheck).mockRejectedValue(new ApiError('Nope'))
		const row = mountRow()
		const radios = row.findAll('input[type="radio"]')
		await radios[0]!.setValue(true)
		await flushPromises()
		expect((radios[2]!.element as HTMLInputElement).checked).toBe(true)
	})

	test('without a requirement only Off can be chosen, and the row says why', () => {
		const row = mountRow(makeCheck({
			mode: { configured: 'protect', effective: 'off', reason: 'requirement', missing: 'memory_cache', default: 'protect' },
			requirements: [{ id: 'memory_cache', met: false, text: 'Needs a memory cache (APCu, Redis or Memcached).' }],
		}))
		expect(row.findAll('input[type="radio"]').map((r) => (r.element as HTMLInputElement).disabled)).toEqual([false, true, true])
		expect(row.text()).toContain('Needs a memory cache')
	})

	test('learning mode is left to the header', () => {
		const row = mountRow(makeCheck({ mode: { configured: 'protect', effective: 'observe', reason: 'learning', missing: null, default: 'protect' } }))
		expect(row.text()).not.toContain('Runs as')
		expect(row.text()).not.toContain('learning')
	})

	test('"Customise" opens the full card, which starts collapsed', async () => {
		const row = mountRow()
		expect(row.text()).not.toContain('How it decides')
		const customise = row.get('[data-test="customise"]')
		expect(customise.attributes('aria-expanded')).toBe('false')
		await customise.trigger('click')
		expect(customise.attributes('aria-expanded')).toBe('true')
		expect(row.text()).toContain('How it decides')
		expect(row.text()).toContain('Save changes')
	})

	test('a link to the check opens "Customise"', () => {
		const row = mountRow(makeCheck(), true)
		expect(row.text()).toContain('How it decides')
	})
})
