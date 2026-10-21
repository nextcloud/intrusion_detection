/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { ApiError, isRateLimited } from './api.ts'

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
