/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Param } from '../types.ts'

import { describe, expect, test } from 'vitest'
import { httpsUrlProblem, isCidr, listIdProblem, validateParam } from './validate.ts'

const rules = (type: Param['type'], min: number | null = null, max: number | null = null, choices: string[] = []) => ({ type, min, max, choices })

describe('validateParam', () => {
	test('whole numbers within the range', () => {
		const param = rules('int', 3, 1000)
		expect(validateParam(param, '10')).toEqual({ value: 10 })
		expect(validateParam(param, 25)).toEqual({ value: 25 })
		expect(validateParam(param, '2').error).toBe('Enter at least 3.')
		expect(validateParam(param, '1001').error).toBe('Enter at most 1,000.')
		expect(validateParam(param, '1,000')).toEqual({ value: 1000 })
		expect(validateParam(rules('int'), '200 000')).toEqual({ value: 200000 })
		expect(validateParam(rules('int'), '20,00').error).toBe('Enter a whole number.')
		expect(validateParam(param, '1.5').error).toBe('Enter a whole number.')
		expect(validateParam(param, 'ten').error).toBe('Enter a whole number.')
		expect(validateParam(param, '').error).toBe('Enter a whole number.')
	})

	test('durations explain their range as durations', () => {
		const param = rules('duration', 60, 3600)
		expect(validateParam(param, 600)).toEqual({ value: 600 })
		expect(validateParam(param, 30).error).toBe('Enter at least 1 minute.')
		expect(validateParam(param, 7200).error).toBe('Enter at most 1 hour.')
		expect(validateParam(param, '10m').error).toBe('Enter a whole number.')
	})

	test('numbers with a fraction', () => {
		const param = rules('float', 0, 1)
		expect(validateParam(param, '0.5')).toEqual({ value: 0.5 })
		expect(validateParam(param, '0,25')).toEqual({ value: 0.25 })
		expect(validateParam(param, '2').error).toBe('Enter at most 1.')
		expect(validateParam(param, 'x').error).toBe('Enter a number.')
	})

	test('switches and choices', () => {
		expect(validateParam(rules('bool'), true)).toEqual({ value: true })
		expect(validateParam(rules('bool'), 'yes').error).toBeDefined()
		const choice = rules('choice', null, null, ['off', 'daily', 'weekly'])
		expect(validateParam(choice, 'daily')).toEqual({ value: 'daily' })
		expect(validateParam(choice, 'hourly').error).toBe('Choose one of: off, daily, weekly.')
	})

	test('lists are entered one per line, trimmed and without duplicates', () => {
		expect(validateParam(rules('string_list'), ' admin \nroot\n\nadmin')).toEqual({ value: ['admin', 'root'] })
		expect(validateParam(rules('string_list'), ['a', 'b'])).toEqual({ value: ['a', 'b'] })
		expect(validateParam(rules('cidr_list'), '192.0.2.0/24\n2001:db8::/32')).toEqual({ value: ['192.0.2.0/24', '2001:db8::/32'] })
		expect(validateParam(rules('cidr_list'), '192.0.2.0/33').error).toBe('This entry is not valid: 192.0.2.0/33')
		expect(validateParam(rules('cidr_list'), 'example.com').error).toBe('This entry is not valid: example.com')
	})
})

describe('isCidr', () => {
	test.each([
		['203.0.113.7', true],
		['203.0.113.0/24', true],
		['2001:db8:1:2::/64', true],
		['::1', true],
		['256.0.0.1', false],
		['203.0.113.0/24/1', false],
		['203.0.113.0/x', false],
		['localhost', false],
	])('%s → %s', (value, expected) => {
		expect(isCidr(value)).toBe(expected)
	})
})

describe('httpsUrlProblem', () => {
	test('https addresses without credentials are fine', () => {
		expect(httpsUrlProblem('https://lists.example.org/drop.txt')).toBeNull()
	})

	test.each([
		['', 'Enter the address of the list.'],
		['lists.example.org/drop.txt', 'This is not a complete web address. It should look like https://example.org/list.txt.'],
		['http://lists.example.org/drop.txt', 'Only https:// addresses are allowed, so nobody on the way can change the list.'],
		['https://user:secret@lists.example.org/drop.txt', 'The address must not contain a user name or password.'],
	])('%s is refused', (url, message) => {
		expect(httpsUrlProblem(url)).toBe(message)
	})
})

describe('listIdProblem', () => {
	test.each(['corp_feed', 'a1'])('%s is a valid name', (id) => {
		expect(listIdProblem(id)).toBeNull()
	})

	test.each(['', 'Corp', '1list', 'a', 'with space', 'x'.repeat(33)])('"%s" is not', (id) => {
		expect(listIdProblem(id)).not.toBeNull()
	})
})
