<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationOutcome, ConfirmationPolicy, ParamValue } from '../../types.ts'

import { mdiLockOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SelectField from '../common/SelectField.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, updateSettings } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	policies: ConfirmationPolicy[]
	outcomes: ConfirmationOutcome[]
}>()

const emit = defineEmits<{
	/** A policy changed; carries the new list */
	changed: [policies: ConfirmationPolicy[]]
}>()

const KNOWN_DEVICE_SETTING = 'step_up_known_device_ok_for'

const busy = ref<string | null>(null)
/** The texts are shown as text, never as HTML: no escaping needed */
const opts = { escape: false, sanitize: false }
const { announce } = useAnnouncer()

/**
 * @param id - An outcome
 */
function outcomeOf(id: string): ConfirmationOutcome | undefined {
	return props.outcomes.find((outcome) => outcome.id === id)
}

/**
 * Save settings and put the changed policy in place.
 *
 * @param policy - The policy changed
 * @param change - The settings to save
 * @param updated - The policy as it is after saving
 */
async function save(policy: ConfirmationPolicy, change: Record<string, ParamValue>, updated: ConfirmationPolicy) {
	busy.value = policy.id
	try {
		const payload = await updateSettings(change)
		state.settings = payload.settings
		emit('changed', props.policies.map((p) => p.id === policy.id ? updated : p))
		const done = t(APP_ID, 'Saved: {reason}', { reason: policy.label }, undefined, opts)
		showSuccess(done)
		announce(done)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the confirmation policy', { error })
			showError(errorMessage(error, t(APP_ID, 'The change could not be saved. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}

/**
 * @param policy - The policy
 * @param outcome - What happens when nothing can confirm
 */
function setOutcome(policy: ConfirmationPolicy, outcome: string) {
	if (outcome === policy.outcome) {
		return
	}
	void save(policy, { [policy.setting]: outcome }, { ...policy, outcome })
}

/**
 * @param policy - The policy
 * @param on - Whether a remembered device confirms such logins
 */
function setKnownDevice(policy: ConfirmationPolicy, on: boolean) {
	const current = state.settings.find((s) => s.name === KNOWN_DEVICE_SETTING)?.value
	const list = (Array.isArray(current) ? current : []).filter((id) => id !== policy.id)
	if (on) {
		list.push(policy.id)
	}
	void save(policy, { [KNOWN_DEVICE_SETTING]: list }, { ...policy, knownDevice: on })
}
</script>

<template>
	<div :class="$style.wrap">
		<table :class="$style.table" data-test="policies">
			<colgroup>
				<col :class="$style.col_reason">
				<col :class="$style.col_device">
				<col>
			</colgroup>
			<thead>
				<tr>
					<th scope="col">
						{{ t(APP_ID, 'Why the login needs confirmation') }}
					</th>
					<th scope="col">
						{{ t(APP_ID, 'A remembered device confirms it') }}
					</th>
					<th scope="col">
						{{ t(APP_ID, 'If nothing can confirm it') }}
					</th>
				</tr>
			</thead>
			<tbody>
				<tr v-for="policy in policies" :key="policy.id" :data-policy="policy.id">
					<th scope="row">
						<span :class="$style.reason">{{ policy.label }}</span>
						<span :class="$style.why">
							{{ t(APP_ID, 'Default: {outcome}. {why}', { outcome: outcomeOf(policy.default)?.label ?? policy.default, why: policy.why }, undefined, opts) }}
						</span>
					</th>
					<td :data-label="t(APP_ID, 'A remembered device confirms it')">
						<NcCheckboxRadioSwitch
							v-if="policy.knownDeviceAllowed"
							type="switch"
							:modelValue="policy.knownDevice"
							:disabled="busy !== null"
							@update:modelValue="setKnownDevice(policy, $event)">
							{{ policy.knownDevice ? t(APP_ID, 'Yes') : t(APP_ID, 'No') }}
							<span class="hidden-visually">{{ policy.label }}</span>
						</NcCheckboxRadioSwitch>
						<span v-else :class="$style.never">
							<NcIconSvgWrapper inline :path="mdiLockOutline" :size="16" />
							{{ t(APP_ID, 'Never: the password itself is at risk') }}
						</span>
					</td>
					<td :data-label="t(APP_ID, 'If nothing can confirm it')">
						<SelectField
							:class="$style.select"
							:modelValue="policy.outcome"
							:label="t(APP_ID, 'If nothing can confirm: {reason}', { reason: policy.label }, undefined, opts)"
							hideLabel
							:options="outcomes.map((outcome) => ({ value: outcome.id, label: outcome.id === policy.default ? t(APP_ID, '{outcome} (default)', { outcome: outcome.label }, undefined, opts) : outcome.label }))"
							:disabled="busy !== null"
							:aria-describedby="`ids-outcome-${policy.id}-text`"
							@update:modelValue="setOutcome(policy, $event)" />
						<p :id="`ids-outcome-${policy.id}-text`" :class="[$style.effect, { [$style.effect_refuse]: policy.outcome === 'refuse' }]">
							{{ outcomeOf(policy.outcome)?.description }}
						</p>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
</template>

<style module>
.wrap {
	overflow-x: auto;
}

.table {
	width: 100%;
	min-width: 680px;
	border-collapse: collapse;
	table-layout: fixed;
}

.table th,
.table td {
	padding: calc(var(--default-grid-baseline) * 3);
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: top;
	line-height: 1.5;
	white-space: normal;
}

.table thead th {
	padding-block: calc(var(--default-grid-baseline) * 2);
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
}

.table tbody tr:last-child th,
.table tbody tr:last-child td {
	border-bottom: none;
}

.table .col_reason {
	width: 38%;
}

.table .col_device {
	width: 24%;
}

.reason {
	display: block;
	font-weight: 700;
}

.why {
	display: block;
	margin-top: calc(var(--default-grid-baseline) * 1);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	font-weight: normal;
}

.never {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	min-height: var(--default-clickable-area);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.select {
	width: 100%;
	max-width: 420px;
}

.effect {
	margin: calc(var(--default-grid-baseline) * 1.5) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.effect_refuse {
	color: var(--color-main-text);
}

@media (max-width: 760px) {
	.table {
		min-width: 0;
	}

	.table thead,
	.table colgroup {
		display: none;
	}

	.table,
	.table tbody,
	.table tr,
	.table th,
	.table td {
		display: block;
		width: 100% !important;
	}

	.table tr {
		padding-block: calc(var(--default-grid-baseline) * 3);
		border-bottom: 1px solid var(--color-border);
	}

	.table tbody tr:last-child {
		border-bottom: none;
	}

	.table th,
	.table td {
		padding: calc(var(--default-grid-baseline) * 1) 0;
		border: none !important;
	}

	.table td[data-label]::before {
		content: attr(data-label);
		display: block;
		margin-bottom: calc(var(--default-grid-baseline) * 1);
		color: var(--color-text-maxcontrast);
		font-size: 0.8em;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
	}

	.select {
		max-width: none;
	}
}
</style>
