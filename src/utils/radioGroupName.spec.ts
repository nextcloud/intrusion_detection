/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import { defineComponent, h, nextTick, ref } from 'vue'
import ModeSwitch from '../components/checks/ModeSwitch.vue'

/**
 * @param wrapper - Where the radio inputs are
 * @param wrapper.findAll - Finds the inputs
 */
function names(wrapper: { findAll: (selector: string) => { attributes: (name: string) => string | undefined }[] }): (string | undefined)[] {
	return wrapper.findAll('input[type="radio"]').map((input) => input.attributes('name'))
}

describe('the options of a radio group', () => {
	test('share one name, so that the group is one tab stop with arrow keys', async () => {
		const wrapper = mount(ModeSwitch, { props: { modelValue: 'observe', label: 'Mode of Trap URLs' } })
		await nextTick()
		const [first, ...rest] = names(wrapper)
		expect(first).toMatch(/^intrusion-detection-radio-\d+$/)
		expect(rest).toEqual([first, first])
	})

	test('two groups have different names, also after they change', async () => {
		const onlyOff = ref(false)
		const wrapper = mount(defineComponent({
			setup: () => () => [
				h(ModeSwitch, { modelValue: 'off', label: 'A', onlyOff: onlyOff.value }),
				h(ModeSwitch, { modelValue: 'off', label: 'B' }),
			],
		}))
		onlyOff.value = true
		await nextTick()
		const all = names(wrapper)
		expect(new Set(all.slice(0, 3)).size).toBe(1)
		expect(new Set(all.slice(3)).size).toBe(1)
		expect(all[0]).not.toBe(all[3])
	})
})
