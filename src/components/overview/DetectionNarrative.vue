<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, DetectionDetail } from '../../types.ts'

import { mdiContentCopy, mdiFileDocumentAlertOutline, mdiFormatListBulleted, mdiLockOpenVariantOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, inject, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import ReferencePill from '../common/ReferencePill.vue'
import RiskBreakdown from './RiskBreakdown.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { detectionSections } from '../../extensions.ts'
import { incidentRequest } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	detail: DetectionDetail
}>()

const emit = defineEmits<{
	lift: [ban: Ban]
}>()

const id = useId()
const showAttempts = ref(false)
const { announce } = useAnnouncer()

const enforced = computed(() => props.detail.detection.enforced)
const activeBans = computed(() => props.detail.bans.filter((ban) => ban.active))
const sections = computed(() => detectionSections.filter((section) => section.applies(props.detail)))

const showTab = inject<(tab: string) => void>('ids-show-tab', () => undefined)

/**
 * Open the Incidents tab with a report about the account or the address of
 * this detection, for the 7 days before now.
 *
 * @param type - Account or address
 * @param value - The account or the address
 */
function incidentReport(type: 'user' | 'address', value: string) {
	incidentRequest.value = { type, value, since: null, until: null }
	showTab('incidents')
}

/**
 * "Copy as text": the narrative as plain text, e.g. for a ticket.
 */
async function copyText() {
	try {
		await navigator.clipboard.writeText(props.detail.text)
		announce(t(APP_ID, 'The explanation was copied.'))
	} catch {
		announce(t(APP_ID, 'Could not copy. Select the text and copy it by hand.'))
	}
}
</script>

<template>
	<div :class="$style.narrative">
		<section :class="$style.narrative__section">
			<h5 :class="$style.narrative__heading">
				{{ t(APP_ID, 'Why did this happen?') }}
			</h5>
			<p v-for="(sentence, index) in detail.narrative.happened" :key="index" :class="$style.narrative__text">
				{{ sentence }}
			</p>
		</section>

		<RiskBreakdown v-if="detail.risk" :risk="detail.risk" />

		<section :class="$style.narrative__section">
			<h5 :class="$style.narrative__heading">
				{{ enforced ? t(APP_ID, 'What Nextcloud did') : t(APP_ID, 'What Nextcloud would have done') }}
			</h5>
			<ul :class="$style.narrative__done">
				<li v-for="(sentence, index) in detail.narrative.done" :key="index">
					{{ sentence }}
				</li>
			</ul>
			<p v-if="detail.narrative.observedBecause" :class="$style.narrative__muted" data-test="observed-because">
				{{ detail.narrative.observedBecause }}
			</p>
		</section>

		<component
			:is="section.component"
			v-for="section in sections"
			:key="section.id"
			:detail="detail" />

		<section v-if="activeBans.length > 0" :class="$style.narrative__section">
			<h5 :class="$style.narrative__heading">
				{{ t(APP_ID, 'Blocked right now') }}
			</h5>
			<ul :class="$style.narrative__bans">
				<li v-for="ban in activeBans" :key="ban.id" :class="$style.narrative__ban">
					<code>{{ ban.cidr }}</code>
					<ReferencePill :reference="ban.reference" />
					<span :class="$style.narrative__muted">
						{{ t(APP_ID, 'until') }} <NcDateTime :timestamp="ban.expiresAt * 1000" :relativeTime="false" />
					</span>
				</li>
			</ul>
		</section>

		<div :class="$style.narrative__actions">
			<NcButton
				v-for="ban in activeBans"
				:key="ban.id"
				variant="secondary"
				@click="emit('lift', ban)">
				<template #icon>
					<NcIconSvgWrapper :path="mdiLockOpenVariantOutline" />
				</template>
				{{ activeBans.length > 1 ? t(APP_ID, 'Lift block of {address}', { address: ban.cidr }) : t(APP_ID, 'Lift block') }}
			</NcButton>
			<NcButton
				v-if="detail.detection.ip"
				variant="tertiary"
				data-test="show-attempts"
				:aria-expanded="showAttempts ? 'true' : 'false'"
				:aria-controls="`${id}-attempts`"
				@click="showAttempts = !showAttempts">
				<template #icon>
					<NcIconSvgWrapper :path="mdiFormatListBulleted" />
				</template>
				{{ showAttempts ? t(APP_ID, 'Hide attempts') : t(APP_ID, 'Show attempts') }}
			</NcButton>
			<NcButton
				v-if="detail.detection.uid"
				variant="tertiary"
				data-test="incident-report-user"
				@click="incidentReport('user', detail.detection.uid)">
				<template #icon>
					<NcIconSvgWrapper :path="mdiFileDocumentAlertOutline" />
				</template>
				{{ t(APP_ID, 'Incident report for this account') }}
			</NcButton>
			<NcButton
				v-if="detail.detection.ip"
				variant="tertiary"
				data-test="incident-report-address"
				@click="incidentReport('address', detail.detection.ip)">
				<template #icon>
					<NcIconSvgWrapper :path="mdiFileDocumentAlertOutline" />
				</template>
				{{ t(APP_ID, 'Incident report for this address') }}
			</NcButton>
			<NcButton variant="tertiary" @click="copyText">
				<template #icon>
					<NcIconSvgWrapper :path="mdiContentCopy" />
				</template>
				{{ t(APP_ID, 'Copy as text') }}
			</NcButton>
		</div>

		<div v-if="showAttempts" :id="`${id}-attempts`" :class="$style.narrative__attempts">
			<p v-if="!detail.attemptsAvailable" :class="$style.narrative__muted">
				{{ t(APP_ID, 'Details older than 1 hour are not kept; the counts above were saved when the detection was made.') }}
			</p>
			<p v-else-if="detail.attempts.length === 0" :class="$style.narrative__muted">
				{{ t(APP_ID, 'No failed attempts from this address in the last hour.') }}
			</p>
			<table v-else :class="$style.table">
				<caption class="hidden-visually">
					{{ t(APP_ID, 'Failed attempts from this address in the last hour') }}
				</caption>
				<thead>
					<tr>
						<th scope="col">
							{{ t(APP_ID, 'When') }}
						</th>
						<th scope="col">
							{{ t(APP_ID, 'What') }}
						</th>
						<th scope="col">
							{{ t(APP_ID, 'Account') }}
						</th>
					</tr>
				</thead>
				<tbody>
					<tr v-for="(attempt, index) in detail.attempts" :key="index">
						<td><NcDateTime :timestamp="attempt.createdAt * 1000" :relativeTime="false" :format="{ timeStyle: 'medium' }" /></td>
						<td>{{ attempt.label }}</td>
						<td>{{ attempt.uid ?? t(APP_ID, 'not an existing account') }}</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</template>

<style module>
.narrative {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
}

.narrative__section {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
}

.narrative__heading {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.narrative__text {
	margin: 0;
	max-width: 80ch;
	line-height: 1.6;
}

.narrative__done {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.6;
}

.narrative__bans {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.narrative__ban {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.narrative__muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.narrative__actions {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.table {
	width: 100%;
	border-collapse: collapse;
	font-variant-numeric: tabular-nums;
}

.table th {
	color: var(--color-text-maxcontrast);
	font-weight: 600;
	text-align: start;
}

.table th,
.table td {
	padding: calc(var(--default-grid-baseline) * 2);
	border-bottom: 1px solid var(--color-border);
}
</style>
