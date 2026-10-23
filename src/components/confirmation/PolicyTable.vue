<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationOutcome, ConfirmationPolicy, ParamValue } from '../../types.ts'

import { mdiLockOutline } from '@mdi/js'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SelectField from '../common/SelectField.vue'
import { useAction } from '../../composables/useAction.ts'
import { saveSettings, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

const props = defineProps<{
	policies: ConfirmationPolicy[]
	outcomes: ConfirmationOutcome[]
}>()

const KNOWN_DEVICE_SETTING = 'step_up_known_device_ok_for'

const { busy, run } = useAction()
/** The texts are shown as text, never as HTML: no escaping needed */

/**
 * @param id - An outcome
 */
function outcomeOf(id: string): ConfirmationOutcome | undefined {
	return props.outcomes.find((outcome) => outcome.id === id)
}

/**
 * Save the settings of a policy.
 *
 * @param policy - The policy changed
 * @param change - The settings to save
 */
function save(policy: ConfirmationPolicy, change: Record<string, ParamValue>) {
	run(policy.id, () => saveSettings(change), {
		done: t(APP_ID, 'Saved: {reason}', { reason: policy.label }),
		toast: true,
		fallback: t(APP_ID, 'The change could not be saved. Please try again.'),
	})
}

/**
 * @param policy - The policy
 * @param outcome - What happens when nothing can confirm
 */
function setOutcome(policy: ConfirmationPolicy, outcome: string) {
	if (outcome === policy.outcome) {
		return
	}
	save(policy, { [policy.setting]: outcome })
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
	save(policy, { [KNOWN_DEVICE_SETTING]: list })
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
							{{ t(APP_ID, 'Default: {outcome}. {why}', { outcome: outcomeOf(policy.default)?.label ?? policy.default, why: policy.why }) }}
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
							:label="t(APP_ID, 'If nothing can confirm: {reason}', { reason: policy.label })"
							hideLabel
							:options="outcomes.map((outcome) => ({ value: outcome.id, label: outcome.id === policy.default ? t(APP_ID, '{outcome} (default)', { outcome: outcome.label }) : outcome.label }))"
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
	padding: var(--ids-space-3);
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: top;
	line-height: 1.5;
	white-space: normal;
}

.table thead th {
	padding-block: var(--ids-space-2);
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
	composes: muted from '../../styles/shared.module.css';
	display: block;
	margin-top: var(--ids-space-1);
	font-size: 0.9em;
	font-weight: normal;
}

.never {
	composes: muted from '../../styles/shared.module.css';
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1-5);
	min-height: var(--default-clickable-area);
	font-size: 0.9em;
}

.select {
	width: 100%;
	max-width: 420px;
}

.effect {
	margin: var(--ids-space-1-5) 0 0;
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
		padding-block: var(--ids-space-3);
		border-bottom: 1px solid var(--color-border);
	}

	.table tbody tr:last-child {
		border-bottom: none;
	}

	.table th,
	.table td {
		padding: var(--ids-space-1) 0;
		border: none !important;
	}

	.table td[data-label]::before {
		content: attr(data-label);
		display: block;
		margin-bottom: var(--ids-space-1);
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
