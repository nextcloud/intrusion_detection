<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, Detection } from '../../types.ts'

import { mdiClose, mdiShieldCheckOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import EmptyNote from '../common/EmptyNote.vue'
import SelectField from '../common/SelectField.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import DetectionGroup from './DetectionGroup.vue'
import DetectionRow from './DetectionRow.vue'
import { errorMessage, fetchDetections } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { detectionFilters, openDetectionId, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { groupDetections } from '../../utils/groups.ts'

const emit = defineEmits<{
	lift: [ban: Ban, reload: () => Promise<void>]
}>()

const PAGE = 25
const id = useId()
const detections = ref<Detection[]>([])
const hasMore = ref(false)
const loading = ref(true)
const loadingMore = ref(false)
const error = ref<string | null>(null)
const address = ref(detectionFilters.address)
const user = ref(detectionFilters.user)

const severityOptions = [
	{ value: '', label: () => t(APP_ID, 'Any severity') },
	{ value: 'medium,high,critical', label: () => t(APP_ID, 'Medium and above') },
	{ value: 'high,critical', label: () => t(APP_ID, 'High and above') },
	{ value: 'critical', label: () => t(APP_ID, 'Critical only') },
]

/** Configurable checks plus any other check seen in the list, e.g. "Shared address not blocked" */
const checkOptions = computed(() => {
	const options = new Map(state.checks.map((check) => [check.id, check.texts.name]))
	for (const detection of detections.value) {
		if (!options.has(detection.checkId)) {
			options.set(detection.checkId, detection.checkName)
		}
	}
	if (detectionFilters.check !== '' && !options.has(detectionFilters.check)) {
		options.set(detectionFilters.check, detectionFilters.check)
	}
	return [...options.entries()].map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label))
})

/** Runs of detections that read the same are folded into one row */
const entries = computed(() => groupDetections(detections.value))

const filtered = computed(() => Object.values(detectionFilters).some((value) => value !== ''))

/**
 * Load the first page for the current filters.
 */
async function load() {
	loading.value = true
	error.value = null
	try {
		const page = await fetchDetections(detectionFilters, PAGE, 0)
		detections.value = page.detections
		hasMore.value = page.hasMore
	} catch (e) {
		logger.error('Could not load detections', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The detections could not be loaded. Please reload the page.'))
	} finally {
		loading.value = false
	}
}

/**
 * Append the next page.
 */
async function loadMore() {
	loadingMore.value = true
	try {
		const page = await fetchDetections(detectionFilters, PAGE, detections.value.length)
		detections.value.push(...page.detections)
		hasMore.value = page.hasMore
	} catch (e) {
		logger.error('Could not load more detections', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'More detections could not be loaded.'))
	} finally {
		loadingMore.value = false
	}
}

let typing: ReturnType<typeof setTimeout> | undefined
watch([address, user], () => {
	clearTimeout(typing)
	typing = setTimeout(() => {
		detectionFilters.address = address.value.trim()
		detectionFilters.user = user.value.trim()
	}, 400)
})

watch(() => ({ ...detectionFilters }), () => {
	address.value = detectionFilters.address
	user.value = detectionFilters.user
	load()
}, { immediate: true })

/**
 * Remove every filter.
 */
function clearFilters() {
	Object.assign(detectionFilters, { check: '', severity: '', user: '', address: '', mode: '' })
}

/** A detection opened from a link or the lookup that is not on the first page */
const pinned = computed(() => openDetectionId.value !== null && !detections.value.some((d) => d.id === openDetectionId.value) ? openDetectionId.value : null)

/**
 * Reload the list after a block was lifted, so its rows and narratives show the change.
 *
 * @param ban - The block to lift
 * @param reload - Reloads the narrative it was lifted from
 */
function onLift(ban: Ban, reload: () => Promise<void>) {
	emit('lift', ban, async () => {
		await Promise.all([reload(), load()])
	})
}

defineExpose({ reload: load })
</script>

<template>
	<section :class="$style.detections" :aria-labelledby="`${id}-heading`">
		<header :class="$style.detections__head">
			<h3 :id="`${id}-heading`" :class="$style.detections__heading">
				{{ t(APP_ID, 'Recent activity') }}
			</h3>
			<span v-if="!loading" :class="$style.detections__count" aria-live="polite">
				{{ detections.length === 0 ? '' : n(APP_ID, 'Showing %n detection', 'Showing %n detections', detections.length) }}
			</span>
		</header>

		<div
			:class="$style.filters"
			role="group"
			:aria-label="t(APP_ID, 'Filter detections')"
			data-test="detection-filters">
			<SelectField
				v-model="detectionFilters.check"
				:class="$style.filter"
				:label="t(APP_ID, 'Check')"
				:options="[{ value: '', label: t(APP_ID, 'All checks') }, ...checkOptions]" />
			<SelectField
				v-model="detectionFilters.severity"
				:class="$style.filter"
				:label="t(APP_ID, 'Severity')"
				:options="severityOptions.map((option) => ({ value: option.value, label: option.label() }))" />
			<SelectField
				v-model="detectionFilters.mode"
				:class="$style.filter"
				:label="t(APP_ID, 'Outcome')"
				:options="[{ value: '', label: t(APP_ID, 'All outcomes') }, { value: 'enforced', label: t(APP_ID, 'Handled') }, { value: 'observed', label: t(APP_ID, 'Only observed') }]" />
			<div :class="[$style.filter, $style.filter_text]">
				<label :for="`${id}-address`">{{ t(APP_ID, 'Address') }}</label>
				<NcTextField
					:id="`${id}-address`"
					v-model="address"
					labelOutside
					:placeholder="t(APP_ID, 'e.g. {example}', { example: '203.0.113.5' })"
					autocomplete="off"
					spellcheck="false" />
			</div>
			<div :class="[$style.filter, $style.filter_text]">
				<label :for="`${id}-user`">{{ t(APP_ID, 'Account') }}</label>
				<NcTextField
					:id="`${id}-user`"
					v-model="user"
					labelOutside
					:placeholder="t(APP_ID, 'e.g. {example}', { example: 'alice' })"
					autocomplete="off"
					spellcheck="false" />
			</div>
			<NcButton
				v-if="filtered"
				variant="tertiary"
				:class="$style.filters__clear"
				@click="clearFilters">
				<template #icon>
					<NcIconSvgWrapper :path="mdiClose" />
				</template>
				{{ t(APP_ID, 'Clear filters') }}
			</NcButton>
		</div>

		<NcNoteCard v-if="error" type="error" :text="error" />

		<ul v-if="pinned !== null" :class="[$style.detections__list, $style.detections__list_pinned]" :aria-label="t(APP_ID, 'Opened detection')">
			<DetectionRow
				:key="pinned"
				:detectionId="pinned"
				open
				@lift="onLift" />
		</ul>

		<div v-if="loading" :class="$style.detections__skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 5" :key="i" height="44px" />
		</div>

		<EmptyNote
			v-else-if="detections.length === 0 && !error"
			:name="filtered ? t(APP_ID, 'No detections match these filters') : t(APP_ID, 'No attacks recorded')"
			:description="filtered ? t(APP_ID, 'Try fewer filters.') : t(APP_ID, 'When a check finds something, it is listed here with an explanation. Nextcloud is watching.')"
			:icon="mdiShieldCheckOutline" />

		<ul v-else :class="$style.detections__list">
			<template v-for="entry in entries" :key="entry.key">
				<DetectionRow
					v-if="entry.type === 'single'"
					:detection="entry.detection"
					:open="openDetectionId === entry.detection.id"
					@lift="onLift" />
				<DetectionGroup
					v-else
					:detections="entry.detections"
					:openId="openDetectionId"
					@lift="onLift" />
			</template>
		</ul>

		<div v-if="!loading && hasMore" :class="$style.detections__more">
			<NcButton variant="secondary" :disabled="loadingMore" @click="loadMore">
				<template v-if="loadingMore" #icon>
					<NcLoadingIcon />
				</template>
				{{ t(APP_ID, 'Show more') }}
			</NcButton>
		</div>
	</section>
</template>

<style module>
.detections {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
}

.detections__head {
	display: flex;
	flex-wrap: wrap;
	align-items: baseline;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.detections__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.detections__count {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.filters {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 170px), 1fr));
	align-items: start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.filters .filter {
	min-width: 0;
	margin: 0;
}

.filter_text {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.filter_text label {
	font-weight: 600;
}

/* The text fields line up with the selects: no extra space around them */
.filter_text :global(.input-field) {
	margin: 0;
}

.filters .filters__clear {
	align-self: end;
	justify-self: start;
}

.detections__list {
	margin: 0;
	padding: 0;
	list-style: none;
}

.detections__list_pinned {
	border: 1px solid color-mix(in srgb, var(--color-primary-element) 40%, var(--color-border));
	border-radius: var(--border-radius-large);
}

.detections__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.detections__more {
	display: flex;
	justify-content: center;
}

</style>
