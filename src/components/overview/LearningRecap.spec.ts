/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { LearningRecap as Recap } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import LearningRecap from './LearningRecap.vue'
import { closeLearningRecap, fetchLearningRecap } from '../../services/api.ts'
import { useLearningRecap } from '../../stores/overview.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchLearningRecap: vi.fn(),
	closeLearningRecap: vi.fn(() => Promise.resolve()),
}))

/**
 * A recap of a first week with attacks, none of them from one's own people.
 *
 * @param recap - What differs
 */
function makeRecap(recap: Partial<Recap> = {}): Recap {
	return {
		startedAt: 1_760_000_000,
		endedAt: 1_760_604_800,
		days: 7,
		first: true,
		attempts: 2120,
		addresses: 48,
		topAttack: { checkId: 'password_spraying', name: 'Password spraying', summary: 'One password is tried against many different accounts.', attempts: 1500 },
		wouldHaveBlocked: 31,
		ownPeople: 0,
		accounts: [],
		complete: true,
		...recap,
	}
}

describe('the recap of the learning period', () => {
	afterEach(() => {
		vi.mocked(fetchLearningRecap).mockReset()
		vi.mocked(closeLearningRecap).mockClear()
	})

	test('sums up the first week, its top attack and what would have been blocked', () => {
		const wrapper = mount(LearningRecap, { props: { recap: makeRecap() } })
		expect(wrapper.get('#overview-recap h3').text()).toBe('Learning mode is over')
		expect(wrapper.get('[data-test="recap-lead"]').text()).toBe('In your first week: 2,120 attempts from 48 addresses.')
		const figures = wrapper.get('[data-test="recap-figures"]').text()
		expect(figures).toContain('Top attack')
		expect(figures).toContain('Password spraying')
		expect(figures).toContain('One password is tried against many different accounts. Seen 1,500 times.')
		expect(figures).toContain('31')
		expect(figures).toContain('addresses would have been blocked')
		expect(wrapper.get('[data-test="recap-own-people"]').text()).toContain('None of your own people would have been blocked')
		expect(wrapper.find('[data-test="recap-incomplete"]').exists()).toBe(false)
		expect(wrapper.get('button').text()).toBe('Got it')
	})

	test('names the own people who would have been blocked', () => {
		const accounts = [{ uid: 'mia', displayName: 'Mia Wagner' }, { uid: 'noah', displayName: 'noah' }]
		const wrapper = mount(LearningRecap, { props: { recap: makeRecap({ ownPeople: 3, accounts }) } })
		const note = wrapper.get('[data-test="recap-own-people"]')
		expect(note.text()).toContain('3 of your own people would have been blocked')
		expect(note.text()).toContain('These accounts logged in from an address the checks would have blocked.')
		const items = note.get('[data-test="recap-accounts"]').findAll('li').map((item) => item.findAll('strong, span').map((part) => part.text()).join(' ') || item.text())
		expect(items).toEqual(['Mia Wagner (mia)', 'noah', 'and 1 more'])
	})

	test('a quiet week has nothing to block', () => {
		const wrapper = mount(LearningRecap, { props: { recap: makeRecap({ attempts: 0, addresses: 0, topAttack: null, wouldHaveBlocked: 0 }) } })
		expect(wrapper.get('[data-test="recap-lead"]').text()).toBe('A quiet first week: nothing to block.')
		expect(wrapper.find('[data-test="recap-figures"]').exists()).toBe(false)
		expect(wrapper.find('[data-test="recap-own-people"]').exists()).toBe(false)
		expect(wrapper.text()).toContain('No check found anything it would have blocked.')
	})

	test('a later or longer learning period is not "your first week"', () => {
		const later = mount(LearningRecap, { props: { recap: makeRecap({ first: false, days: 3, attempts: 1, addresses: 1 }) } })
		expect(later.get('[data-test="recap-lead"]').text()).toBe('In 3 days of learning: 1 attempt from 1 address.')
		const longer = mount(LearningRecap, { props: { recap: makeRecap({ days: 14 }) } })
		expect(longer.get('[data-test="recap-lead"]').text()).toBe('In your first 14 days: 2,120 attempts from 48 addresses.')
		const quiet = mount(LearningRecap, { props: { recap: makeRecap({ first: false, attempts: 0, wouldHaveBlocked: 0, topAttack: null }) } })
		expect(quiet.get('[data-test="recap-lead"]').text()).toBe('A quiet learning period: nothing to block.')
	})

	test('says when the numbers can be higher', () => {
		const wrapper = mount(LearningRecap, { props: { recap: makeRecap({ complete: false }) } })
		expect(wrapper.get('[data-test="recap-incomplete"]').text()).toContain('the real numbers can be higher')
	})

	test('"Got it" closes it for good', async () => {
		vi.mocked(fetchLearningRecap).mockResolvedValue(makeRecap())
		const Host = defineComponent({
			setup() {
				const { data } = useLearningRecap()
				return () => data.value ? h(LearningRecap, { recap: data.value }) : h('p', 'closed')
			},
		})
		const wrapper = mount(Host)
		await flushPromises()
		await wrapper.get('button').trigger('click')
		await flushPromises()
		expect(closeLearningRecap).toHaveBeenCalledTimes(1)
		expect(wrapper.text()).toBe('closed')
		wrapper.unmount()
	})
})
