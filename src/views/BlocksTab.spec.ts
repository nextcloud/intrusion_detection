/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Ban, CheckRef, Traps } from '../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import BlocksTab from './BlocksTab.vue'
import { fetchBans, fetchTraps } from '../services/api.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchBans: vi.fn(),
	fetchTraps: vi.fn(),
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
	limits: { labelMaxLength: 200, loginNameMaxLength: 64 },
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
		vi.mocked(fetchBans).mockResolvedValue({ bans: [], hasMore: false, activeCount: 0, limits: { minDuration: 300, maxDuration: 7776000, maxNote: 255, levelDurations: [14400, 86400, 604800] } })
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

	test('lists each block in one row with a bare address, the time it ends and a Lift button', async () => {
		const ban = (overrides: Partial<Ban>): Ban => ({ id: '1', reference: 'K7Q2-MPXA', cidr: '203.0.113.7/32', scope: 'ip', level: 1, checkId: 'manual_block', checkName: 'Blocked by an administrator', detectionId: null, createdBy: 'admin', note: 'Scanner', createdAt: 1_760_000_000, expiresAt: 1_760_086_400, liftedAt: null, liftedBy: null, liftNote: null, active: true, ...overrides })
		vi.mocked(fetchBans).mockResolvedValue({ bans: [ban({}), ban({ id: '2', cidr: '198.51.100.0/24', scope: 'net', reference: 'AB12-CD34' })], hasMore: false, activeCount: 2, limits: { minDuration: 300, maxDuration: 7776000, maxNote: 255, levelDurations: [14400, 86400, 604800] } })
		const wrapper = await mountTab()
		const rows = wrapper.findAll('[data-test="ban-row"]')
		expect(rows).toHaveLength(2)
		expect(rows[0]!.text()).toContain('203.0.113.7')
		expect(rows[0]!.text()).not.toContain('/32')
		expect(rows[0]!.text()).toContain('Blocked until')
		expect(rows[0]!.text()).toContain('Scanner')
		expect(rows[1]!.text()).toContain('198.51.100.0/24')
		expect(rows[1]!.text()).toContain('network')
		expect(rows.every((row) => row.find('[data-test="ban-lift"]').exists())).toBe(true)
		expect(rows[0]!.get('[data-test="ban-lift"]').attributes('aria-label')).toBe('Lift the block of 203.0.113.7')
		expect(wrapper.find('table').exists()).toBe(false)
	})

	test('says when the decoys cannot be loaded', async () => {
		vi.mocked(fetchTraps).mockRejectedValue(new Error('down'))
		const wrapper = await mountTab()
		expect(wrapper.text()).toContain('The decoys could not be loaded')
		expect(wrapper.find('#blocks-active').exists()).toBe(true)
	})
})
