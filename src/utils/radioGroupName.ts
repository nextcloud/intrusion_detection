/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Directive } from 'vue'

let groups = 0

/**
 * @param el - The element of the group
 */
function nameRadios(el: HTMLElement): void {
	el.dataset.radioGroup ??= `intrusion-detection-radio-${++groups}`
	for (const input of el.querySelectorAll<HTMLInputElement>('input[type="radio"]')) {
		input.name = el.dataset.radioGroup
	}
}

/**
 * `v-radio-group-name` on an NcRadioGroup: gives its radio inputs one
 * shared name, so that the group is one tab stop and the arrow keys move
 * between its options. NcRadioGroupButton renders its input without a
 * name, which makes every option a group of its own.
 */
export const vRadioGroupName: Directive<HTMLElement> = {
	mounted: nameRadios,
	updated: nameRadios,
}
