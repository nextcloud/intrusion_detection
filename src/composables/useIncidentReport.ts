/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { IncidentSubjectType } from '../types.ts'

import { inject } from 'vue'
import { incidentRequest } from '../store.ts'

/**
 * "Create incident report": open the Incidents tab with a report about an
 * account or an address, for the 7 days before now.
 */
export function useIncidentReport() {
	const showTab = inject<(tab: string) => void>('ids-show-tab', () => undefined)

	/**
	 * @param type - Account or address
	 * @param value - The account or the address
	 */
	function createReport(type: IncidentSubjectType, value: string) {
		incidentRequest.value = { type, value, since: null, until: null }
		showTab('incidents')
	}

	return { createReport }
}
