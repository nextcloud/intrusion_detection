<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Contribution } from '../../types.ts'

import { mdiEarth, mdiRefresh, mdiScaleBalance } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import CodeBlock from '../common/CodeBlock.vue'
import SectionCard from '../common/SectionCard.vue'
import StateBadge from '../common/StateBadge.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError, errorMessage, isCancelled, updateContribution } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { httpsUrlProblem } from '../../utils/validate.ts'

const props = defineProps<{
	contribution: Contribution
	/** Reloads the preview */
	refreshing?: boolean
}>()

const emit = defineEmits<{
	changed: [contribution: Contribution]
	refresh: []
}>()

const address = ref(props.contribution.url)
const addressError = ref<string | null>(null)
const busy = ref<string | null>(null)
const { announce } = useAnnouncer()

watch(() => props.contribution.url, (value) => {
	address.value = value
})

const addressProblem = computed(() => address.value.trim() === '' ? null : httpsUrlProblem(address.value))
const payload = computed(() => JSON.stringify(props.contribution.preview.payload, null, 2))
const reports = computed(() => props.contribution.preview.payload.reports.length)

/**
 * @param key - What is saved
 * @param change - The change
 * @param change.enabled - Send reports
 * @param change.url - Where to
 * @param done - What to announce
 */
async function save(key: string, change: { enabled?: boolean, url?: string }, done: string) {
	busy.value = key
	addressError.value = null
	try {
		emit('changed', await updateContribution(change))
		announce(done)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not change the contribution', { error })
			if (key === 'url' && error instanceof ApiError) {
				addressError.value = error.message
			} else {
				showError(errorMessage(error, t(APP_ID, 'The change could not be saved. Please try again.')))
			}
		}
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<SectionCard :heading="contribution.texts.name" :icon="mdiEarth" level="h4">
		<template #description>
			{{ contribution.texts.summary }}
		</template>
		<template #actions>
			<StateBadge :type="contribution.enabled ? 'success' : 'neutral'">
				{{ contribution.enabled ? t(APP_ID, 'On') : t(APP_ID, 'Off') }}
			</StateBadge>
		</template>

		<p :class="$style.text">
			{{ contribution.texts.sent }}
		</p>

		<div :class="$style.privacy" role="note">
			<NcIconSvgWrapper inline :path="mdiScaleBalance" :size="20" />
			<p>{{ contribution.texts.privacy }}</p>
		</div>

		<NcCheckboxRadioSwitch
			type="switch"
			:modelValue="contribution.enabled"
			:loading="busy === 'enabled'"
			:disabled="busy !== null"
			@update:modelValue="save('enabled', { enabled: $event }, $event ? t(APP_ID, 'Contributing is on.') : t(APP_ID, 'Contributing is off.'))">
			{{ t(APP_ID, 'Send the reports below once a day') }}
		</NcCheckboxRadioSwitch>

		<form :class="$style.url" @submit.prevent="save('url', { url: address.trim() }, t(APP_ID, 'Saved'))">
			<NcTextField
				v-model="address"
				:class="$style.url__field"
				:label="t(APP_ID, 'Send reports to')"
				placeholder="https://blocklist.example.org/v1/reports"
				type="url"
				spellcheck="false"
				:error="(addressProblem ?? addressError) !== null"
				:helperText="addressProblem ?? addressError ?? ''"
				:disabled="busy !== null" />
			<NcButton type="submit" variant="secondary" :disabled="busy !== null || addressProblem !== null || address.trim() === contribution.url">
				<template v-if="busy === 'url'" #icon>
					<NcLoadingIcon />
				</template>
				{{ t(APP_ID, 'Save') }}
			</NcButton>
		</form>

		<div :class="$style.preview">
			<div :class="$style.preview__head">
				<div>
					<h5 :class="$style.preview__heading">
						{{ t(APP_ID, 'Live preview of the next report') }}
					</h5>
					<p :class="$style.muted">
						{{ contribution.texts.status }}
						{{ n(APP_ID, '%n address in it.', '%n addresses in it.', reports) }}
						<template v-if="contribution.preview.truncated">
							{{ t(APP_ID, 'More were blocked; the rest follow in the next days.') }}
						</template>
					</p>
				</div>
				<NcButton variant="tertiary" :disabled="refreshing" @click="emit('refresh')">
					<template #icon>
						<NcLoadingIcon v-if="refreshing" />
						<NcIconSvgWrapper v-else :path="mdiRefresh" />
					</template>
					{{ t(APP_ID, 'Refresh') }}
				</NcButton>
			</div>
			<CodeBlock :content="payload" :label="t(APP_ID, 'The next report')" file="POST · application/json" />
			<p v-if="contribution.lastAttemptAt" :class="$style.muted">
				{{ t(APP_ID, 'Last run:') }} <NcDateTime :timestamp="contribution.lastAttemptAt * 1000" />
				<template v-if="contribution.lastSuccessAt">
					· {{ n(APP_ID, '%n address sent last time', '%n addresses sent last time', contribution.lastReports) }}
				</template>
				<template v-if="contribution.lastError">
					· {{ t(APP_ID, 'The last run failed: {error}', { error: contribution.lastError }) }}
				</template>
			</p>
		</div>
	</SectionCard>
</template>

<style module>
.text {
	margin: 0;
	line-height: 1.6;
}

.muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.privacy {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-warning) 12%, var(--color-main-background));
}

.privacy > :first-child {
	flex: 0 0 auto;
	margin-top: 2px;
	color: var(--color-warning-text);
}

.privacy p {
	margin: 0;
	line-height: 1.6;
}

.url {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
}

.url__field {
	flex: 1 1 280px;
	max-width: 520px;
}

.url > button {
	margin-top: calc(var(--default-grid-baseline) * 1.5);
}

.preview {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.preview__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.preview__heading {
	margin: 0 0 calc(var(--default-grid-baseline) * 1);
	font-size: 1em;
	font-weight: 700;
}
</style>
