<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban } from '../../types.ts'

import { mdiClose, mdiFileDocumentAlertOutline, mdiLockOpenVariantOutline, mdiMagnify } from '@mdi/js'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import ReferencePill from '../common/ReferencePill.vue'
import SeverityPill from '../common/SeverityPill.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { useIncidentReport } from '../../composables/useIncidentReport.ts'
import { useLookup } from '../../stores/overview.ts'
import { APP_ID, formatAddress, outcomeLabel } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const emit = defineEmits<{
	openDetection: [id: string]
	lift: [ban: Ban]
}>()

const query = ref('')
/** What was looked up; the result follows it, also after a block was lifted */
const submitted = ref<string | null>(null)
const { data: result, error, loading: searching, reload } = useLookup(submitted, { failure: () => t(APP_ID, 'The lookup did not work. Please try again.') })
const { announce } = useAnnouncer()
const { createReport } = useIncidentReport()

/** The account or address an incident report can be made about */
const reportSubject = computed(() => {
	const found = result.value
	if (found?.kind === 'address') {
		return { type: 'address' as const, value: found.query }
	}
	if (found?.kind === 'user' && found.user) {
		return { type: 'user' as const, value: found.user.uid }
	}
	return null
})

const heading = computed(() => {
	const found = result.value
	if (found === null) {
		return ''
	}
	switch (found.kind) {
		case 'reference':
			return t(APP_ID, 'Block {reference}', { reference: found.bans[0]?.reference ?? found.query })
		case 'address':
			return t(APP_ID, 'Address {address}', { address: found.query })
		case 'user':
			return found.user && found.user.displayName !== found.user.uid
				? t(APP_ID, 'Account {account} ({name})', { account: found.user.uid, name: found.user.displayName })
				: t(APP_ID, 'Account {account}', { account: found.user?.uid ?? found.query })
		default:
			return t(APP_ID, 'Nothing found for "{query}"', { query: found.query })
	}
})

/** A search the user started is announced once its result is in */
let announceNext = false
watch(result, (found) => {
	if (announceNext && found !== null) {
		announceNext = false
		announce(found.kind === 'none' ? t(APP_ID, 'Nothing found.') : heading.value)
	}
})
watch(error, () => {
	announceNext = false
})

/**
 * Look up what was typed.
 */
function search() {
	const q = query.value.trim()
	if (q === '') {
		return
	}
	announceNext = true
	if (submitted.value === q) {
		reload()
	} else {
		submitted.value = q
	}
}

/**
 * Empty the box and the result.
 */
function clear() {
	query.value = ''
	submitted.value = null
}
</script>

<template>
	<div :class="$style.lookup">
		<form :class="$style.lookup__form" role="search" @submit.prevent="search">
			<NcTextField
				v-model="query"
				:class="$style.lookup__field"
				:label="t(APP_ID, 'Address or account')"
				:placeholder="t(APP_ID, 'e.g. {example}', { example: t(APP_ID, 'K7Q2-MPXA, 203.0.113.7 or alice') })"
				:showTrailingButton="query !== ''"
				:trailingButtonLabel="t(APP_ID, 'Clear')"
				autocomplete="off"
				spellcheck="false"
				@trailingButtonClick="clear">
				<template #icon>
					<NcIconSvgWrapper :path="mdiMagnify" :size="20" />
				</template>
				<template #trailing-button-icon>
					<NcIconSvgWrapper :path="mdiClose" :size="20" />
				</template>
			</NcTextField>
			<NcButton type="submit" variant="secondary" :disabled="query.trim() === '' || searching">
				<template v-if="searching" #icon>
					<NcLoadingIcon />
				</template>
				{{ t(APP_ID, 'Look up') }}
			</NcButton>
		</form>
		<p :class="$style.lookup__hint">
			{{ t(APP_ID, 'A blocked visitor sees a reference such as K7Q2-MPXA. Type it here to see the block and why it happened.') }}
		</p>

		<NcNoteCard v-if="error" type="error" :text="error" />

		<section
			v-if="result"
			:class="$style.result"
			:aria-label="heading"
			data-test="lookup-result">
			<header :class="$style.result__head">
				<h4 :class="$style.result__title">
					{{ heading }}
				</h4>
				<NcButton variant="tertiary" :aria-label="t(APP_ID, 'Close the result')" @click="clear">
					<template #icon>
						<NcIconSvgWrapper :path="mdiClose" />
					</template>
				</NcButton>
			</header>

			<p v-if="result.kind === 'none'" :class="$style.result__muted">
				{{ t(APP_ID, 'Try a reference like K7Q2-MPXA, an address like 203.0.113.7, or an account name.') }}
			</p>

			<template v-else>
				<p v-if="result.kind === 'address' && result.bans.length === 0" :class="$style.result__muted">
					{{ t(APP_ID, 'This address is not blocked right now.') }}
				</p>
				<ul v-if="result.bans.length > 0" :class="$style.result__list">
					<li v-for="ban in result.bans" :key="ban.id" :class="$style.result__ban">
						<span :class="$style.result__banMain">
							<code>{{ formatAddress(ban.cidr) }}</code>
							<ReferencePill :reference="ban.reference" />
							<span v-if="ban.active" :class="$style.result__muted">
								{{ t(APP_ID, 'blocked until') }} <TimeStamp :timestamp="ban.expiresAt" />
							</span>
							<span v-else :class="$style.result__muted">
								{{ ban.liftedAt ? t(APP_ID, 'lifted by {admin}', { admin: ban.liftedBy ?? '' }) : t(APP_ID, 'ended') }}
							</span>
						</span>
						<span :class="$style.result__muted">{{ ban.checkName }}<template v-if="ban.note"> · {{ ban.note }}</template></span>
						<NcButton v-if="ban.active" variant="secondary" @click="emit('lift', ban)">
							<template #icon>
								<NcIconSvgWrapper :path="mdiLockOpenVariantOutline" />
							</template>
							{{ t(APP_ID, 'Lift block') }}
						</NcButton>
					</li>
				</ul>

				<template v-if="result.detections.length > 0">
					<h5 :class="$style.result__subheading">
						{{ n(APP_ID, '%n detection in the last 30 days', '%n detections in the last 30 days', result.detections.length) }}
					</h5>
					<ul :class="$style.result__list">
						<li v-for="detection in result.detections" :key="detection.id">
							<button type="button" :class="$style.result__detection" @click="emit('openDetection', detection.id)">
								<SeverityPill :severity="detection.severity" />
								<span :class="$style.result__detectionName">{{ detection.checkName }}</span>
								<span :class="$style.result__muted">{{ outcomeLabel(detection.outcome) }}</span>
								<TimeStamp :class="$style.result__muted" :timestamp="detection.lastSeenAt" short />
							</button>
						</li>
					</ul>
				</template>
				<p v-else-if="result.kind !== 'reference'" :class="$style.result__muted">
					{{ t(APP_ID, 'No detections in the last 30 days.') }}
				</p>

				<div v-if="reportSubject">
					<NcButton variant="secondary" data-test="lookup-incident-report" @click="createReport(reportSubject.type, reportSubject.value)">
						<template #icon>
							<NcIconSvgWrapper :path="mdiFileDocumentAlertOutline" />
						</template>
						{{ t(APP_ID, 'Create incident report') }}
					</NcButton>
				</div>
			</template>
		</section>
	</div>
</template>

<style module>
.lookup {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.lookup__form {
	display: flex;
	max-width: 640px;
	align-items: flex-end;
	gap: var(--ids-space-2);
}

.lookup__field {
	flex: 1 1 auto;
	min-width: 0;
}

.lookup__form > :last-child {
	flex: 0 0 auto;
}

.lookup__hint {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	font-size: 0.9em;
}

.result {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	margin-top: var(--ids-space-2);
	padding: var(--ids-space-4);
	border: 1px solid color-mix(in srgb, var(--color-primary-element) 35%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-primary-element) 5%, var(--color-main-background));
}

.result__head {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.result__title {
	margin: 0;
	font-size: 1.05em;
	font-weight: 700;
}

.result__subheading {
	composes: eyebrow from '../../styles/shared.module.css';
	margin: 0;
}

.result__muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.result__list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.result__ban {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.result__banMain {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
}

.result button.result__detection {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-3);
	width: 100%;
	margin: 0;
	padding: var(--ids-space-2);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.result button.result__detection:hover {
	background-color: var(--color-background-hover);
}

.result button.result__detection:focus-visible {
	outline: var(--ids-focus-ring);
}

.result__detectionName {
	font-weight: 600;
}
</style>
