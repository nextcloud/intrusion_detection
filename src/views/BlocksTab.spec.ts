/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { CheckRef, Traps } from '../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import BlocksTab from './BlocksTab.vue'
import { fetchBans, fetchTraps } from '../services/api.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchBans: vi.fn(),
	fetchTraps: vi.fn(),
	fetchChecks: vi.fn(() => new Promise(() => {})),
}))

const check = (id: string): CheckRef => ({ id, name: id, mode: { configured: 'protect', effective: 'protect', reason: null, missing: null, default: 'protect' } })

const traps: Traps = {
	decoys: [],
	decoyCheck: check('decoy_credential'),
	reservedCheck: check('reserved_name'),
	trapCheck: check('trap_url'),
	decoyCollisions: [],
	reservedNames: { names: ['root'] } as unknown as Traps['reservedNames'],
	trapPaths: {} as Traps['trapPaths'],
}

const stubs = {
	BlocklistsPanel: { template: '<section data-test="blocklists" />' },
	FirewallExportPanel: { template: '<section data-test="firewall" />' },
	DecoyCredentials: { template: '<section data-test="decoys" />' },
	ReservedNamesCard: { template: '<section data-test="reserved" />' },
	TrapPathsCard: { template: '<section data-test="trap-paths" />' },
	SettingsGroup: { template: '<div data-test="settings-group"><slot :fill="() => []" :changed="[]" /></div>' },
	AddBanDialog: true,
	LiftBanDialog: true,
}

/**
 * Mount the tab with no blocks and the given decoys.
 */
async function mountTab() {
	const wrapper = mount(BlocksTab, { global: { stubs } })
	await flushPromises()
	return wrapper
}

describe('the Blocks tab', () => {
	beforeEach(() => {
		vi.mocked(fetchBans).mockResolvedValue({ bans: [], hasMore: false, activeCount: 0 })
		vi.mocked(fetchTraps).mockResolvedValue(traps)
	})

	test('shows the blocks, the lists, the decoys and the reserved names', async () => {
		const wrapper = await mountTab()
		expect(wrapper.find('#blocks-active').exists()).toBe(true)
		expect(wrapper.text()).toContain('Block an address')
		for (const part of ['blocklists', 'decoys', 'reserved']) {
			expect(wrapper.find(`[data-test="${part}"]`).exists(), part).toBe(true)
		}
	})

	test('shows the trap paths, the firewall export and escalation below them', async () => {
		const wrapper = await mountTab()
		expect(wrapper.find('[data-test="trap-paths"]').exists()).toBe(true)
		expect(wrapper.find('[data-test="firewall"]').exists()).toBe(true)
		expect(wrapper.get('#blocks-escalation').text()).toContain('How blocks escalate')
		expect(wrapper.text()).toContain('Addresses that are never blocked')
		expect(wrapper.text()).toContain('Locked yourself out?')
	})

	test('says when the decoys cannot be loaded', async () => {
		vi.mocked(fetchTraps).mockRejectedValue(new Error('down'))
		const wrapper = await mountTab()
		expect(wrapper.text()).toContain('The decoys could not be loaded')
		expect(wrapper.find('#blocks-active').exists()).toBe(true)
	})
})
