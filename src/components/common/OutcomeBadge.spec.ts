/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import OutcomeBadge from './OutcomeBadge.vue'

describe('the outcome of a detection', () => {
	test('says "Acted on" only when Nextcloud acted', () => {
		const label = (outcome: 'acted' | 'notified' | 'recorded' | 'observed') => mount(OutcomeBadge, { props: { outcome } }).text()
		expect(label('acted')).toBe('Acted on')
		expect(label('notified')).toBe('Notified')
		expect(label('recorded')).toBe('Recorded')
		expect(label('observed')).toBe('Observed')
	})
})
