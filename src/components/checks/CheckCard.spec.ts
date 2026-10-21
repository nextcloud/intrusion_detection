/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import CheckCard from './CheckCard.vue'
import { ApiError, updateCheck } from '../../services/api.ts'
import { state } from '../../store.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	updateCheck: vi.fn(),
	resetCheck: vi.fn(),
	fetchStatus: vi.fn(() => new Promise(() => {})),
}))

/**
 * Mount an expanded card.
 *
 * @param check - The check
 */
function mountCard(check = makeCheck()) {
	return mount(CheckCard, { props: { check, open: true }, attachTo: document.body })
}

describe('CheckCard', () => {
	beforeEach(() => {
		state.settings = [
			{ name: 'ban_duration_1', type: 'duration', default: 14400, min: 300, max: 7776000, choices: [], value: 14400, label: 'First block', help: '', unit: '', group: 'blocks' },
		]
		state.checks = []
	})

	afterEach(() => {
		vi.mocked(updateCheck).mockReset()
		document.body.innerHTML = ''
	})

	test('shows the decision sentence with the current values', () => {
		const card = mountCard()
		const decides = card.get('[data-test="decides"]')
		expect(decides.text()).toBe('Fires when one address fails to log in 10 times for at least 5 different accounts within 10 minutes.')
		expect(decides.findAll('strong').map((s) => s.attributes('data-setting'))).toEqual(['min_failures', 'min_names', 'window'])
		card.unmount()
	})

	test('the live sentence follows the fields while typing', async () => {
		const card = mountCard()
		const inputs = card.findAll('input[type="text"]')
		// The duration's number comes first, then the two whole numbers.
		await inputs[1]!.setValue('25')
		expect(card.get('[data-test="decides"]').text()).toContain('fails to log in 25 times')
		await inputs[0]!.setValue('30')
		expect(card.get('[data-test="decides"]').text()).toContain('within 30 minutes')
		await inputs[0]!.setValue('1')
		await card.get('select').setValue('3600')
		expect(card.get('[data-test="decides"]').text()).toContain('within 1 hour')
		// Above the maximum of 1 hour: the sentence shows the saved value and the field says why.
		await inputs[0]!.setValue('4')
		expect(card.get('[data-test="decides"]').text()).toContain('within 10 minutes')
		expect(card.text()).toContain('Enter at most 1 hour.')
		card.unmount()
	})

	test('durations are formatted like the server while typing', async () => {
		const card = mountCard()
		await card.findAll('input[type="text"]')[0]!.setValue('90')
		await card.get('select').setValue('1')
		expect(card.get('[data-test="decides"]').text()).toContain('within 90 seconds')
		await card.findAll('input[type="text"]')[0]!.setValue('120')
		expect(card.get('[data-test="decides"]').text()).toContain('within 2 minutes')
		card.unmount()
	})

	test('invalid values are explained before saving, and saving is disabled', async () => {
		const card = mountCard()
		await card.findAll('input[type="text"]')[1]!.setValue('2')
		expect(card.text()).toContain('Enter at least 3.')
		// The sentence shows the saved value.
		expect(card.get('[data-test="decides"]').text()).toContain('fails to log in 10 times')
		const save = card.findAll('button').find((b) => b.text() === 'Save changes')!
		expect(save.attributes('disabled')).toBeDefined()
		await card.find('form').trigger('submit')
		expect(updateCheck).not.toHaveBeenCalled()
		card.unmount()
	})

	test('saves only the changed settings and shows the server answer', async () => {
		const saved = makeCheck({ params: makeCheck().params.map((p) => p.name === 'min_failures' ? { ...p, value: 20 } : p) })
		vi.mocked(updateCheck).mockResolvedValue(saved)
		const card = mountCard()
		await card.findAll('input[type="text"]')[1]!.setValue('20')
		await card.find('form').trigger('submit')
		await flushPromises()
		expect(updateCheck).toHaveBeenCalledWith('credential_stuffing', { params: { min_failures: 20 }, responses: undefined })
		card.unmount()
	})

	test('a server error about a setting is shown at that field', async () => {
		vi.mocked(updateCheck).mockRejectedValue(new ApiError('"min_failures" must be at most 1000.', 'min_failures'))
		const card = mountCard()
		await card.findAll('input[type="text"]')[1]!.setValue('999')
		await card.find('form').trigger('submit')
		await flushPromises()
		expect(card.text()).toContain('"min_failures" must be at most 1000.')
		card.unmount()
	})

	test('the selected responses build "What happens", with settings filled in', async () => {
		const card = mountCard()
		expect(card.get('[data-test="happens"]').text()).toBe('The address is blocked for 4 hours.')
		const notify = card.findAll('input[type="checkbox"]').find((input) => input.attributes('value') === 'notify_admin')!
		await notify.setValue(true)
		expect(card.get('[data-test="happens"]').findAll('li').map((li) => li.text())).toEqual([
			'The address is blocked for 4 hours.',
			'Notify the administrators.',
		])
		card.unmount()
	})

	test('the mode switch saves at once and is a radio group', async () => {
		vi.mocked(updateCheck).mockResolvedValue(makeCheck({ mode: { configured: 'observe', effective: 'observe', reason: null, missing: null, default: 'protect' } }))
		const card = mountCard()
		const group = card.get('[role="radiogroup"], fieldset')
		const radios = group.findAll('input[type="radio"]')
		expect(radios).toHaveLength(3)
		await radios[1]!.setValue(true)
		await radios[1]!.trigger('change')
		await flushPromises()
		expect(updateCheck).toHaveBeenCalledTimes(1)
		expect(updateCheck).toHaveBeenCalledWith('credential_stuffing', { mode: 'observe' })
		card.unmount()
	})

	test('a failed mode change goes back to the saved mode', async () => {
		vi.mocked(updateCheck).mockRejectedValue(new ApiError('Nope'))
		const card = mountCard()
		const radios = card.findAll('input[type="radio"]')
		await radios[0]!.setValue(true)
		await flushPromises()
		expect((radios[2]!.element as HTMLInputElement).checked).toBe(true)
		card.unmount()
	})

	test('without a requirement only Off can be chosen, and the card says why', () => {
		const card = mountCard(makeCheck({
			mode: { configured: 'protect', effective: 'off', reason: 'requirement', missing: 'memory_cache', default: 'protect' },
			requirements: [{ id: 'memory_cache', met: false, text: 'Needs a memory cache (APCu, Redis or Memcached).' }],
		}))
		const radios = card.findAll('input[type="radio"]')
		expect(radios.map((r) => (r.element as HTMLInputElement).disabled)).toEqual([false, true, true])
		expect(card.text()).toContain('Needs a memory cache')
		expect(card.text()).toContain('This check cannot run on this server')
		card.unmount()
	})

	test('the badge counts the last 7 days, and learning mode is explained', () => {
		const card = mountCard(makeCheck({ mode: { configured: 'protect', effective: 'observe', reason: 'learning', missing: null, default: 'protect' } }))
		expect(card.text()).toContain('Fired 12 times · 9 addresses blocked')
		expect(card.text()).toContain('Observing while learning')
		card.unmount()
	})
})
