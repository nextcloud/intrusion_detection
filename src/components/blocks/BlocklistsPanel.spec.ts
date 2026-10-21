/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Blocklist, Blocklists, CheckRef } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import BlocklistsPanel from './BlocklistsPanel.vue'
import { fetchBlocklists, updateCheck } from '../../services/api.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchBlocklists: vi.fn(),
	updateCheck: vi.fn(),
}))

vi.mock('../../store.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	refreshStatus: vi.fn(),
}))

const check = (id: string): CheckRef => ({ id, name: id, mode: { configured: 'observe', effective: 'observe', reason: null, missing: null, default: 'observe' } })

/**
 * @param id - The list
 * @param builtin - Shipped with the app
 */
function list(id: string, builtin: boolean): Blocklist {
	return {
		id,
		name: `List ${id}`,
		url: `https://lists.example.org/${id}`,
		format: 'cidr',
		purpose: 'deny',
		mode: 'observe',
		enabled: true,
		builtin,
		interval: 21600,
		customInterval: false,
		termsUrl: null,
		reference: null,
		ranges: 10,
		entries: 10,
		skipped: 0,
		lastAttemptAt: null,
		lastSuccessAt: 1_760_000_000,
		lastFailureAt: null,
		lastError: null,
		lastErrorText: null,
		failures: 0,
		stale: false,
		matches: [],
	}
}

const lists: Blocklists = {
	lists: [list('drop', true), list('corp', false)],
	countsMatches: false,
	matchDays: 30,
	check: check('blocklist'),
	networkCheck: check('risky_network'),
	maxLists: 20,
	minInterval: 3600,
	maxInterval: 604800,
	formats: ['cidr'],
}

/**
 * Mount the panel with a built-in and an own list.
 */
async function mountPanel(overrides: Partial<Blocklists> = {}) {
	vi.mocked(fetchBlocklists).mockResolvedValue({ ...structuredClone(lists), ...overrides })
	const wrapper = mount(BlocklistsPanel, { global: { stubs: { AddBlocklistDialog: true, MatchSparkline: true } } })
	await flushPromises()
	return wrapper
}

describe('the blocklists', () => {
	test('show the built-in and your own lists, adding a list and the details, which start collapsed', async () => {
		const wrapper = await mountPanel()
		expect(wrapper.text()).toContain('List drop')
		expect(wrapper.text()).toContain('List corp')
		expect(wrapper.text()).toContain('Use List drop')
		expect(wrapper.text()).toContain('Add a list')
		expect(wrapper.text()).toContain('Sync now')
		expect(wrapper.text()).toContain('Downloaded from')
		const toggles = wrapper.findAll('button[aria-controls]')
		expect(toggles.length).toBeGreaterThan(0)
		expect(toggles.every((toggle) => toggle.attributes('aria-expanded') === 'false')).toBe(true)
	})

	test('a blocklist switched on while its check is off offers to set the check to Observe', async () => {
		const off = { ...check('blocklist'), mode: { configured: 'off' as const, effective: 'off' as const, reason: null, missing: null, default: 'observe' as const } }
		vi.mocked(updateCheck).mockResolvedValue({ id: 'blocklist', mode: { ...off.mode, configured: 'observe', effective: 'observe' } } as never)
		const wrapper = await mountPanel({ check: off })
		const note = wrapper.get('[data-test="deny-check-off"]')
		expect(note.text()).toContain('are not downloaded')
		await note.get('button').trigger('click')
		await flushPromises()
		expect(updateCheck).toHaveBeenCalledWith('blocklist', { mode: 'observe' })
		expect(wrapper.find('[data-test="deny-check-off"]').exists()).toBe(false)
	})
})
