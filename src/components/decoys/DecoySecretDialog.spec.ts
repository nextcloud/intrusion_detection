/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { NewDecoy } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { nextTick } from 'vue'
import DecoyCredentials from './DecoyCredentials.vue'
import DecoySecretDialog from './DecoySecretDialog.vue'
import { createDecoy } from '../../services/api.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	createDecoy: vi.fn(),
	deleteDecoy: vi.fn(),
}))

const SECRET = 'wJxeW-bj8eB-R5koJ-357nA-sRcxw'

const created: NewDecoy = {
	decoy: { id: 3, label: 'Old backup script on nas01', loginName: 'backup-svc', format: 'app-password', createdBy: 'admin', createdAt: 1_790_000_000, lastTriggeredAt: null, triggerCount: 0 },
	secret: SECRET,
}

/**
 * A button of the open dialog, by its text.
 *
 * @param text - The button text
 */
function button(text: string): HTMLButtonElement | undefined {
	return [...document.body.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)
}

describe('DecoySecretDialog', () => {
	let writeText: ReturnType<typeof vi.fn>

	beforeEach(() => {
		writeText = vi.fn(() => Promise.resolve())
		Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
	})

	afterEach(() => {
		document.body.innerHTML = ''
	})

	test('shows the secret once, and closes only after it was copied or stored', async () => {
		const wrapper = mount(DecoySecretDialog, { props: { created: { ...created } }, attachTo: document.body })
		await flushPromises()
		expect(document.body.querySelector('[data-test="decoy-secret"]')?.textContent).toBe(SECRET)
		expect(document.body.textContent).toContain('This is the only time the secret is shown')
		expect(document.body.textContent).toContain('Where to plant it')
		expect(button('Done')?.disabled).toBe(true)

		;(document.body.querySelector('[data-test="copy-secret"]') as HTMLButtonElement).click()
		await flushPromises()
		expect(writeText).toHaveBeenCalledWith(SECRET)
		expect(button('Done')?.disabled).toBe(false)

		button('Done')!.click()
		await flushPromises()
		expect(wrapper.emitted('update:created')?.at(-1)).toEqual([null])
		wrapper.unmount()
	})

	test('the checkbox also allows closing when copying is not possible', async () => {
		writeText.mockRejectedValue(new Error('denied'))
		mount(DecoySecretDialog, { props: { created: { ...created } }, attachTo: document.body })
		await flushPromises()
		;(document.body.querySelector('[data-test="copy-secret"]') as HTMLButtonElement).click()
		await flushPromises()
		expect(button('Done')?.disabled).toBe(true)
		const checkbox = document.body.querySelector('input[data-test="secret-stored"], [data-test="secret-stored"] input') as HTMLInputElement
		checkbox.click()
		await flushPromises()
		expect(button('Done')?.disabled).toBe(false)
	})

	test('after the dialog closes, the secret is nowhere on the page', async () => {
		vi.mocked(createDecoy).mockResolvedValue({ ...created })
		const wrapper = mount(DecoyCredentials, {
			props: { decoys: [], check: { id: 'decoy_credential', name: 'Decoys', mode: { configured: 'protect', effective: 'protect', reason: null, missing: null, default: 'protect' } }, collisions: [] },
			attachTo: document.body,
		})
		// The create dialog hands the new decoy over, as after a successful request.
		wrapper.findComponent({ name: 'CreateDecoyDialog' }).vm.$emit('created', { ...created })
		await flushPromises()
		expect(document.body.innerHTML).toContain(SECRET)
		expect(wrapper.emitted('changed')?.[0]?.[0]).toEqual([created.decoy])
		expect(JSON.stringify(wrapper.emitted('changed'))).not.toContain(SECRET)

		;(document.body.querySelector('input[data-test="secret-stored"], [data-test="secret-stored"] input') as HTMLInputElement).click()
		await nextTick()
		button('Done')!.click()
		await flushPromises()
		expect(document.body.innerHTML).not.toContain(SECRET)
		wrapper.unmount()
	})
})
