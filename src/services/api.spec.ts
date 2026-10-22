/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { describe, expect, test, vi } from 'vitest'
import { ApiError, approveRequest, isRateLimited, rejectRequest } from './api.ts'

vi.mock('@nextcloud/axios', async (importOriginal) => ({
	...(await importOriginal<object>()),
	default: { post: vi.fn(() => Promise.resolve({ data: { ocs: { meta: {}, data: {} } } })) },
}))

/**
 * @param status - The HTTP status of the answer
 */
function httpError(status: number): Error {
	return Object.assign(new Error('Request failed'), { isAxiosError: true, response: { status, data: '' } })
}

describe('a refusal for too many requests', () => {
	test('is told apart from other failures, also when the server explained it', () => {
		expect(isRateLimited(httpError(429))).toBe(true)
		expect(isRateLimited(new ApiError('Slow down', null, { cause: httpError(429) }))).toBe(true)
		expect(isRateLimited(httpError(500))).toBe(false)
		expect(isRateLimited(new ApiError('Not valid'))).toBe(false)
		expect(isRateLimited(new Error('down'))).toBe(false)
	})
})

describe('a decision on a request for approval', () => {
	test('approving asks for the password, rejecting does not', async () => {
		await approveRequest(7)
		await rejectRequest(7)
		const [approve, reject] = vi.mocked(axios.post).mock.calls
		expect(approve?.[0]).toMatch(/\/approvals\/7\/approve$/)
		expect(approve?.[2]).toEqual({ confirmPassword: PwdConfirmationMode.Lax })
		expect(reject?.[0]).toMatch(/\/approvals\/7\/reject$/)
		expect(reject?.[2]).toBeUndefined()
	})
})
