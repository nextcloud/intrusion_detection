/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { PersonalActivity } from './types.ts'

import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { activity, overview, securityEvent } from '../tests/personalFixtures.ts'
import { confirmEvent, fetchActivity, fetchKnownDevices, fetchOverview, fetchStaleCredentials, logOutElsewhere } from './api.ts'
import { answerEvent, logOutOtherBrowsers, personal, reloadActivity } from './store.ts'

vi.mock('./api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	confirmEvent: vi.fn(),
	fetchActivity: vi.fn(),
	fetchKnownDevices: vi.fn(),
	fetchOverview: vi.fn(),
	fetchStaleCredentials: vi.fn(),
	logOutElsewhere: vi.fn(),
}))

describe('the personal store', () => {
	afterEach(() => {
		vi.clearAllMocks()
	})

	test('an answered question does not come back from a load that was under way', async () => {
		const question = securityEvent(1, { asks: true, canConfirm: true })
		personal.activity = activity({ questions: [question] })
		vi.mocked(fetchOverview).mockResolvedValue(overview())
		let late!: (value: PersonalActivity) => void
		vi.mocked(fetchActivity)
			.mockReturnValueOnce(new Promise((resolve) => {
				late = resolve
			}))
			.mockResolvedValueOnce(activity({ questions: [] }))
		void reloadActivity()

		vi.mocked(confirmEvent).mockResolvedValue({ ...question, verdict: 'confirmed', verdictAt: 1 })
		await answerEvent(1, 'confirm')
		late(activity({ questions: [question] }))
		await flushPromises()
		expect(personal.activity?.questions).toEqual([])
	})

	test('logging out the other browsers loads the unused app passwords and devices again', async () => {
		personal.staleCredentials = [{ id: 7, name: 'Firefox on Linux', kind: 'session', lastUsed: 1 }]
		vi.mocked(logOutElsewhere).mockResolvedValue({ sessions: 1, devices: 0 })
		vi.mocked(fetchKnownDevices).mockResolvedValue([])
		vi.mocked(fetchStaleCredentials).mockResolvedValue([])
		await logOutOtherBrowsers()
		expect(fetchStaleCredentials).toHaveBeenCalledOnce()
		expect(personal.staleCredentials).toEqual([])
	})
})
