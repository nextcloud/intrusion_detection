/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { LoginApproval } from './types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { addBan, approveRequest, fetchBans, fetchProtectionLevel, fetchStatus, fetchWaitingLogins, updateCheck } from './services/api.ts'
import { banAdd, decideLogin, saveCheck, state, waitingLogins } from './store.ts'
import { useBanList } from './stores/blocks.ts'
import { makeCheck, makeStatus } from './tests/fixtures.ts'

vi.mock('./services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	addBan: vi.fn(),
	approveRequest: vi.fn(),
	fetchBans: vi.fn(),
	fetchProtectionLevel: vi.fn(),
	fetchStatus: vi.fn(),
	fetchWaitingLogins: vi.fn(),
	updateCheck: vi.fn(),
}))

/**
 * @param id - The request
 */
function approval(id: number): LoginApproval {
	return { id, uid: 'alice', displayName: 'Alice', ip: null, createdAt: 1, expiresAt: 2, canDecide: true }
}

describe('the admin store', () => {
	beforeEach(() => {
		vi.mocked(fetchStatus).mockResolvedValue(makeStatus())
		vi.mocked(fetchProtectionLevel).mockResolvedValue({ level: 'custom' })
		vi.mocked(fetchBans).mockResolvedValue({ bans: [], hasMore: false, activeCount: 0 })
	})

	afterEach(() => {
		vi.clearAllMocks()
	})

	test('adding a block loads the status and the shown block list again', async () => {
		vi.mocked(addBan).mockResolvedValue({ id: 1 } as never)
		mount(defineComponent({
			setup() {
				useBanList(false)
				return () => h('div')
			},
		}))
		await flushPromises()
		expect(fetchBans).toHaveBeenCalledTimes(1)

		await banAdd({ target: '203.0.113.7', level: 1, note: '' })
		expect(fetchStatus).toHaveBeenCalledTimes(1)
		expect(fetchBans).toHaveBeenCalledTimes(2)
	})

	test('a new mode leaves the protection level, new settings load it again', async () => {
		state.checks = [makeCheck()]
		vi.mocked(updateCheck).mockResolvedValue(makeCheck())
		await saveCheck('credential_stuffing', { mode: 'observe' })
		expect(fetchStatus).toHaveBeenCalled()
		expect(fetchProtectionLevel).not.toHaveBeenCalled()

		await saveCheck('credential_stuffing', { params: { min_failures: 20 } })
		expect(fetchProtectionLevel).toHaveBeenCalledTimes(1)
		expect(state.protectionLevel).toBe('custom')
	})

	test('a decided login leaves the list at once, before the list is loaded again', async () => {
		waitingLogins.value = [approval(7), approval(8)]
		vi.mocked(approveRequest).mockResolvedValue({})
		let answer!: (value: LoginApproval[]) => void
		vi.mocked(fetchWaitingLogins).mockReturnValue(new Promise((resolve) => {
			answer = resolve
		}))
		await decideLogin(7, true)
		expect(waitingLogins.value.map((a) => a.id)).toEqual([8])
		expect(fetchWaitingLogins).toHaveBeenCalledTimes(1)
		answer([])
		await flushPromises()
		expect(waitingLogins.value).toEqual([])
	})
})
