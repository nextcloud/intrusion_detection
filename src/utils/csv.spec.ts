/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { csvCell } from './csv.ts'

describe('csvCell', () => {
	test('quotes the value and doubles its quotes', () => {
		expect(csvCell('alice')).toBe('"alice"')
		expect(csvCell('Alice "Al" Smith')).toBe('"Alice ""Al"" Smith"')
	})

	test.each(['=1+1', '+1', '-1', '@SUM(A1)', '\t=1', '\r=1', '\0=1'])('defuses %j', (value) => {
		expect(csvCell(value)).toBe(`"'${value}"`)
	})

	test('leaves a formula character later in the value alone', () => {
		expect(csvCell('a=b')).toBe('"a=b"')
	})
})
