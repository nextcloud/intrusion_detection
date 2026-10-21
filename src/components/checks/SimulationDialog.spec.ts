/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Simulation } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import CheckCard from './CheckCard.vue'
import { simulateCheck } from '../../services/api.ts'
import { makeCheck } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	simulateCheck: vi.fn(),
	updateCheck: vi.fn(),
}))

const simulation: Simulation = {
	check: 'credential_stuffing',
	testAddress: '198.51.100.23',
	mode: 'observe',
	modeReason: 'learning',
	runs: true,
	acts: false,
	severity: 'medium',
	narrative: {
		title: 'Credential stuffing',
		happened: ['Between 9:48 and 9:57 the address 198.51.100.23 failed to log in 10 times, trying 5 different accounts.'],
		done: ['Would have: Block the address for hours, longer if it comes back.'],
		observedBecause: 'Nothing was done, because learning mode was on.',
	},
	responses: [{ type: 'ban', text: 'The address is blocked for 4 hours.' }],
}

describe('Simulate on a check card', () => {
	afterEach(() => {
		document.body.innerHTML = ''
		vi.mocked(simulateCheck).mockReset()
	})

	test('runs the simulation on the server and shows what would be reported and done', async () => {
		vi.mocked(simulateCheck).mockResolvedValue(simulation)
		const card = mount(CheckCard, { props: { check: makeCheck(), open: true }, attachTo: document.body })
		await card.findAll('button').find((b) => b.text() === 'Simulate')!.trigger('click')
		await flushPromises()
		expect(simulateCheck).toHaveBeenCalledWith('credential_stuffing')
		const narrative = document.body.querySelector('[data-test="simulation-narrative"]')
		expect(narrative?.textContent).toContain('198.51.100.23 failed to log in 10 times')
		expect(document.body.textContent).toContain('Nothing is recorded, blocked or notified')
		expect(document.body.textContent).toContain('Learning mode is on, so the detection would only be recorded')
		expect(document.body.querySelector('[data-test="simulation-responses"]')?.textContent).toContain('The address is blocked for 4 hours.')
		card.unmount()
	})

	test('checks that cannot be simulated have no button', () => {
		const card = mount(CheckCard, { props: { check: makeCheck({ simulatable: false }), open: true } })
		expect(card.findAll('button').some((b) => b.text() === 'Simulate')).toBe(false)
	})

	test('settings that a card section edits itself are left out of the settings form', async () => {
		const check = makeCheck({
			id: 'reserved_name',
			params: [{ name: 'names', type: 'string_list', default: [], min: null, max: null, choices: [], value: ['admin'], label: 'Reserved names', help: '', unit: '' }],
		})
		const card = mount(CheckCard, { props: { check, open: true } })
		await vi.dynamicImportSettled()
		await flushPromises()
		expect(card.find('textarea').exists()).toBe(false)
		expect(card.text()).toContain('1 name is reserved: admin')
		expect(card.text()).toContain('Manage them on the Decoys tab')
	})
})
