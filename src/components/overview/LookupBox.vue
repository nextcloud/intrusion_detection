<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, LookupResult } from '../../types.ts'

import { mdiClose, mdiLockOpenVariantOutline, mdiMagnify } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import ReferencePill from '../common/ReferencePill.vue'
import SeverityPill from '../common/SeverityPill.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, lookup } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

const emit = defineEmits<{
	openDetection: [id: number]
	lift: [ban: Ban, reload: () => Promise<void>]
}>()

const query = ref('')
const result = ref<LookupResult | null>(null)
const error = ref<string | null>(null)
const searching = ref(false)
const { announce } = useAnnouncer()

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

/**
 * Look up what was typed.
 */
async function search() {
	const q = query.value.trim()
	if (q === '') {
		return
	}
	searching.value = true
	error.value = null
	try {
		result.value = await lookup(q)
		announce(result.value.kind === 'none' ? t(APP_ID, 'Nothing found.') : heading.value)
	} catch (e) {
		logger.error('Lookup failed', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The lookup did not work. Please try again.'))
	} finally {
		searching.value = false
	}
}

/**
 * Empty the box and the result.
 */
function clear() {
	query.value = ''
	result.value = null
	error.value = null
}
</script>

<template>
	<div :class="$style.lookup">
		<form :class="$style.lookup__form" role="search" @submit.prevent="search">
			<NcTextField
				v-model="query"
				:class="$style.lookup__field"
				:label="t(APP_ID, 'Look up a reference, address or user')"
				:placeholder="t(APP_ID, 'K7Q2-MPXA, 203.0.113.7 or alice')"
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
							<code>{{ ban.cidr }}</code>
							<ReferencePill :reference="ban.reference" />
							<span v-if="ban.active" :class="$style.result__muted">
								{{ t(APP_ID, 'blocked until') }} <TimeStamp :timestamp="ban.expiresAt" />
							</span>
							<span v-else :class="$style.result__muted">
								{{ ban.liftedAt ? t(APP_ID, 'lifted by {admin}', { admin: ban.liftedBy ?? '' }) : t(APP_ID, 'ended') }}
							</span>
						</span>
						<span :class="$style.result__muted">{{ ban.checkName }}<template v-if="ban.note"> · {{ ban.note }}</template></span>
						<NcButton v-if="ban.active" variant="secondary" @click="emit('lift', ban, search)">
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
								<span :class="$style.result__muted">{{ detection.enforced ? t(APP_ID, 'Acted on') : t(APP_ID, 'Observed') }}</span>
								<TimeStamp :class="$style.result__muted" :timestamp="detection.lastSeenAt" short />
							</button>
						</li>
					</ul>
				</template>
				<p v-else-if="result.kind !== 'reference'" :class="$style.result__muted">
					{{ t(APP_ID, 'No detections in the last 30 days.') }}
				</p>
			</template>
		</section>
	</div>
</template>

<style module>
.lookup {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.lookup__form {
	display: flex;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) * 2);
}

.lookup__field {
	flex: 1 1 auto;
	min-width: 0;
}

.lookup__form > :last-child {
	flex: 0 0 auto;
}

.lookup__hint {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.result {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	margin-top: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid color-mix(in srgb, var(--color-primary-element) 35%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-primary-element) 5%, var(--color-main-background));
}

.result__head {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.result__title {
	margin: 0;
	font-size: 1.05em;
	font-weight: 700;
}

.result__subheading {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.result__muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.result__list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.result__ban {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.result__banMain {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.result button.result__detection {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	width: 100%;
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 2);
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
	outline: 2px solid var(--color-main-text);
}

.result__detectionName {
	font-weight: 600;
}
</style>
