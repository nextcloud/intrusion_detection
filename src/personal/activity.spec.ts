/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { describe, expect, test } from 'vitest'
import { activityItem, login, NOW, securityChange, securityEvent } from '../tests/personalFixtures.ts'
import { changeValues, confirmationLabel, dayBefore, dayLabel, groupByDay, hasNews, isOpenQuestion } from './activity.ts'

describe('the activity timeline', () => {
	test('is grouped per day, newest day first and newest entry first within a day', () => {
		const items = [
			activityItem({ login: login(1, { createdAt: NOW - 600 }) }),
			activityItem({ failed: 4, at: NOW - 86400 - 60 }),
			activityItem({ change: securityChange(1, { createdAt: NOW - 60 }) }),
			activityItem({ event: securityEvent(1, { createdAt: NOW - 86400 * 3 }) }),
			activityItem({ login: login(2, { createdAt: NOW - 86400 - 3600 }) }),
		]

		const days = groupByDay(items)

		expect(days.map((d) => d.day)).toEqual(['2026-10-21', '2026-10-20', '2026-10-18'])
		expect(days[0].items.map((i) => i.id)).toEqual(['change-1', 'login-1'])
		expect(days[1].items.map((i) => i.id)).toEqual(['failed-2026-10-20', 'login-2'])
		expect(days[2].items.map((i) => i.id)).toEqual(['event-1'])
		expect(groupByDay([])).toEqual([])
	})

	test('names today and yesterday, and spells out older days', () => {
		expect(dayBefore('2026-03-01')).toBe('2026-02-28')
		expect(dayBefore('2027-01-01')).toBe('2026-12-31')
		expect(dayLabel('2026-10-21', '2026-10-21')).toBe('Today')
		expect(dayLabel('2026-10-20', '2026-10-21')).toBe('Yesterday')
		expect(dayLabel('2026-10-15', '2026-10-21')).toBe('Thursday, October 15')
	})

	test('says nothing when only the login of this session is in it', () => {
		const current = activityItem({ login: login(1, { current: true }) })
		expect(hasNews([])).toBe(false)
		expect(hasNews([current])).toBe(false)
		expect(hasNews([current, activityItem({ login: login(2) })])).toBe(true)
		expect(hasNews([activityItem({ failed: 1, at: NOW })])).toBe(true)
	})

	test('an answered question is no longer open', () => {
		expect(isOpenQuestion(securityEvent(1, { asks: true }))).toBe(true)
		expect(isOpenQuestion(securityEvent(1, { asks: true, verdict: 'confirmed', verdictAt: NOW }))).toBe(false)
		expect(isOpenQuestion(securityEvent(1, { asks: false }))).toBe(false)
	})

	test('puts logins and changes in plain words', () => {
		expect(confirmationLabel(login(1, { confirmedBy: 'email_code' }))).toBe('Confirmed with an email code')
		expect(confirmationLabel(login(1, { stepUp: 'refused' }))).toBe('Refused')
		expect(confirmationLabel(login(1)), 'Nothing to say about an ordinary login').toBeNull()
		expect(changeValues(securityChange(1, { previous: 'a***@old.example', new: 'a***@example.com' }))).toBe('from a***@old.example to a***@example.com')
		expect(changeValues(securityChange(1, { detail: 'TOTP' }))).toBe('TOTP')
	})
})
