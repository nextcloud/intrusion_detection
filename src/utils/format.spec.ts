/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { fillTemplate, fillTemplateText, formatDuration, formatValue, splitDuration } from './format.ts'

describe('formatDuration', () => {
	test.each([
		[1, '1 second'],
		[90, '90 seconds'],
		[60, '1 minute'],
		[600, '10 minutes'],
		[5400, '90 minutes'],
		[3600, '1 hour'],
		[14400, '4 hours'],
		[86400, '1 day'],
		[90000, '25 hours'],
		[604800, '7 days'],
	])('%i seconds read as "%s", like the server', (seconds, text) => {
		expect(formatDuration(seconds)).toBe(text)
	})
})

describe('splitDuration', () => {
	test('uses the largest whole unit', () => {
		expect(splitDuration(600)).toEqual({ amount: 10, unit: 60 })
		expect(splitDuration(14400)).toEqual({ amount: 4, unit: 3600 })
		expect(splitDuration(604800)).toEqual({ amount: 7, unit: 86400 })
		expect(splitDuration(90)).toEqual({ amount: 90, unit: 1 })
	})
})

describe('formatValue', () => {
	test('formats like the server', () => {
		expect(formatValue(true)).toBe('on')
		expect(formatValue(false)).toBe('off')
		expect(formatValue([])).toBe('none')
		expect(formatValue(['admin', 'root'])).toBe('admin, root')
		expect(formatValue(0.5, 'float')).toBe('0.5')
		expect(formatValue(0.333333, 'float')).toBe('0.33')
		expect(formatValue(600, 'duration')).toBe('10 minutes')
		expect(formatValue(600, 'int')).toBe('600')
	})
})

describe('fillTemplate', () => {
	const template = 'Fires when one address fails {min_failures} times within {window}.'

	test('fills settings as tokens', () => {
		expect(fillTemplate(template, { min_failures: 10, window: 600 }, { min_failures: 'int', window: 'duration' })).toEqual([
			{ text: 'Fires when one address fails ' },
			{ text: '10', name: 'min_failures' },
			{ text: ' times within ' },
			{ text: '10 minutes', name: 'window' },
			{ text: '.' },
		])
	})

	test('keeps placeholders without a value, as the server does', () => {
		expect(fillTemplateText(template, { window: 3600 }, { window: 'duration' })).toBe('Fires when one address fails {min_failures} times within 1 hour.')
	})

	test('never interprets values as markup', () => {
		const segments = fillTemplate('Name: {names}', { names: ['<b>x</b>'] })
		expect(segments[1]).toEqual({ text: '<b>x</b>', name: 'names' })
	})

	test('a template without placeholders is one segment', () => {
		expect(fillTemplate('Plain text.', {})).toEqual([{ text: 'Plain text.' }])
	})
})
