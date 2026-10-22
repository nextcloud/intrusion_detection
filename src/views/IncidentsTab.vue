<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentReport, IncidentRequest } from '../types.ts'
import type { IncidentSubject } from '../utils/incidents.ts'

import { mdiPlus, mdiShieldCheckOutline, mdiTextBoxSearchOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, nextTick, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import IncidentDetail from '../components/incidents/IncidentDetail.vue'
import IncidentForm from '../components/incidents/IncidentForm.vue'
import IncidentList from '../components/incidents/IncidentList.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { buildIncidentReport, errorMessage, isCancelled, isRateLimited } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { incidentRequest } from '../store.ts'
import { useRecentDetections } from '../stores/overview.ts'
import { APP_ID } from '../utils/format.ts'
import { incidentSubjects, requestKey, subjectKey } from '../utils/incidents.ts'

/** This many built reports are kept for this page view */
const CACHE_SIZE = 10

const recent = useRecentDetections({ failure: () => t(APP_ID, 'The recent incidents could not be loaded.') })
const subjects = computed<IncidentSubject[]>(() => incidentSubjects(recent.data.value?.detections ?? []))
const listLoading = computed(() => recent.data.value === null && recent.error.value === null)
const listError = recent.error
const listHasMore = computed(() => recent.data.value?.hasMore ?? false)

const detail = ref<InstanceType<typeof IncidentDetail> | null>(null)
const report = ref<IncidentReport | null>(null)
/** The request the shown report was built from; set together with the report, so downloads match it */
const built = ref<IncidentRequest | null>(null)
/**
 * Reports built in this page view, least recently shown first. Going back
 * to one shows it again without a new build, so no new audit entry.
 */
const cache = new Map<string, { request: IncidentRequest, report: IncidentReport }>()
/** Counts the builds; only the answer to the latest one is shown */
let latestBuild = 0
const loading = ref(false)
const error = ref<string | null>(null)
const failed = ref<IncidentRequest | null>(null)
const formOpen = ref(false)
/** What the form starts with: the shown report's request, or nothing for a new one */
const formRequest = ref<IncidentRequest | null>(null)
const { announce } = useAnnouncer()

const selected = computed(() => {
	const request = error.value !== null ? failed.value : built.value
	return request ? subjectKey(request.type, request.value) : null
})
const nothingAtAll = computed(() => !listLoading.value && listError.value === null && subjects.value.length === 0
	&& report.value === null && !loading.value && error.value === null)

/**
 * Show a built report and remember it for this page view.
 *
 * @param request - The request it was built from
 * @param result - The report
 * @param focus - Move the focus to the report
 */
async function show(request: IncidentRequest, result: IncidentReport, focus: boolean) {
	const key = requestKey(request)
	cache.delete(key)
	cache.set(key, { request, report: result })
	for (const old of cache.keys()) {
		if (cache.size <= CACHE_SIZE) {
			break
		}
		cache.delete(old)
	}
	built.value = request
	report.value = result
	error.value = null
	failed.value = null
	loading.value = false
	announce(n(APP_ID, 'The report is ready: %n entry.', 'The report is ready: %n entries.', result.entries.length))
	if (focus) {
		await nextTick()
		detail.value?.focus()
	}
}

/**
 * Build the report and show it. A report built before in this page view,
 * such as the one shown, is shown again without a new build. Only the
 * answer to the latest build is shown; a cancelled password prompt leaves
 * the shown report as it is.
 *
 * @param request - Subject and period
 * @param focus - Move the focus to the report once it is shown
 */
async function build(request: IncidentRequest, focus = false) {
	const ticket = ++latestBuild
	const cached = cache.get(requestKey(request))
	if (cached) {
		await show(cached.request, cached.report, focus)
		return
	}
	loading.value = true
	error.value = null
	failed.value = null
	try {
		const result = await buildIncidentReport(request)
		if (ticket === latestBuild) {
			await show(request, result, focus)
		}
	} catch (e) {
		if (ticket !== latestBuild || isCancelled(e)) {
			return
		}
		logger.error('Could not build the incident report', { error: e })
		error.value = isRateLimited(e)
			? t(APP_ID, 'You built many reports in a short time. Try again in a few minutes.')
			: errorMessage(e, t(APP_ID, 'The report could not be built. Please try again.'))
		failed.value = request
		announce(error.value)
	} finally {
		if (ticket === latestBuild) {
			loading.value = false
		}
	}
}

/**
 * @param subject - The address or account picked from the list
 */
function select(subject: IncidentSubject) {
	build({ type: subject.type, value: subject.value, since: null, until: null }, true)
}

/**
 * Open the form, empty or with the request of the shown report.
 *
 * @param request - What the form starts with
 */
function openForm(request: IncidentRequest | null) {
	formRequest.value = request
	formOpen.value = true
}

/**
 * @param request - Subject and period from the form
 */
function submitForm(request: IncidentRequest) {
	formOpen.value = false
	build(request, true)
}

// "Incident report for this account / address" from a detection or a lookup.
watch(incidentRequest, (request) => {
	if (request === null) {
		return
	}
	incidentRequest.value = null
	build(request)
}, { immediate: true, flush: 'post' })
</script>

<template>
	<div :class="$style.tab">
		<header :class="$style.tab__head">
			<div :class="$style.tab__intro">
				<h3 :class="$style.tab__heading">
					{{ t(APP_ID, 'Incidents') }}
				</h3>
				<p :class="$style.tab__description">
					{{ t(APP_ID, 'One timeline of everything Nextcloud knows about an account or an address in a period. Use it to investigate, and as the basis of a breach notification. Reports are built when you ask for them, never stored, and written to the audit log.') }}
				</p>
			</div>
			<NcButton variant="primary" data-test="incident-new" @click="openForm(null)">
				<template #icon>
					<NcIconSvgWrapper :path="mdiPlus" />
				</template>
				{{ t(APP_ID, 'New incident report') }}
			</NcButton>
		</header>

		<NcEmptyContent
			v-if="nothingAtAll"
			:class="$style.tab__empty"
			:name="t(APP_ID, 'No incidents in the last 7 days')"
			:description="t(APP_ID, 'No detection involved an address or an account. To look into one anyway, create an incident report.')"
			data-test="incidents-empty">
			<template #icon>
				<NcIconSvgWrapper :path="mdiShieldCheckOutline" />
			</template>
		</NcEmptyContent>

		<div v-else :class="$style.tab__layout">
			<IncidentList
				:class="$style.tab__list"
				:subjects="subjects"
				:selected="selected"
				:loading="listLoading"
				:error="listError"
				:hasMore="listHasMore"
				@select="select" />

			<div :class="$style.tab__detail">
				<div
					v-if="loading"
					:class="$style.tab__skeleton"
					aria-busy="true"
					:aria-label="t(APP_ID, 'Building the report …')">
					<SkeletonBlock height="28px" width="50%" />
					<SkeletonBlock height="96px" />
					<SkeletonBlock height="64px" />
					<SkeletonBlock height="64px" />
				</div>

				<NcNoteCard v-else-if="error" type="error">
					<p>{{ error }}</p>
					<NcButton
						v-if="failed"
						variant="secondary"
						:class="$style.tab__retry"
						@click="build(failed, true)">
						{{ t(APP_ID, 'Try again') }}
					</NcButton>
				</NcNoteCard>

				<IncidentDetail
					v-else-if="report && built"
					ref="detail"
					:report="report"
					:request="built"
					@change="openForm(built)" />

				<NcEmptyContent
					v-else
					:class="$style.tab__placeholder"
					:name="t(APP_ID, 'Choose an incident')"
					:description="t(APP_ID, 'Its report shows what happened, what Nextcloud did, and what is still open.')"
					data-test="incident-placeholder">
					<template #icon>
						<NcIconSvgWrapper :path="mdiTextBoxSearchOutline" />
					</template>
				</NcEmptyContent>
			</div>
		</div>

		<NcDialog
			v-model:open="formOpen"
			:name="formRequest ? t(APP_ID, 'Change the report') : t(APP_ID, 'New incident report')"
			size="normal">
			<IncidentForm :initial="formRequest" @build="submitForm" />
		</NcDialog>
	</div>
</template>

<style module>
.tab {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-6);
	container-type: inline-size;
}

.tab__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: var(--ids-space-4);
}

.tab__intro {
	flex: 1 1 360px;
	min-width: 0;
}

.tab__heading {
	margin: 0;
	font-size: 1.25em;
	font-weight: 700;
}

.tab__description {
	composes: muted from '../styles/shared.module.css';
	margin: var(--ids-space-1) 0 0;
	max-width: 75ch;
	line-height: 1.5;
}

.tab__layout {
	display: grid;
	grid-template-columns: minmax(0, 1fr);
	gap: var(--ids-space-6);
}

.tab__detail {
	min-width: 0;
}

.tab__skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.tab__retry {
	margin-block-start: var(--ids-space-2);
}

/* On narrow screens the list comes first and a report opens below it */
.tab__placeholder {
	display: none;
}

@container (min-width: 820px) {
	.tab__layout {
		grid-template-columns: minmax(240px, 300px) minmax(0, 1fr);
		gap: var(--ids-space-8);
	}

	.tab__list {
		position: sticky;
		top: var(--ids-space-2);
		align-self: start;
		max-height: calc(100vh - var(--header-height, 50px) - var(--ids-space-8));
		overflow-y: auto;
		padding-inline-end: var(--ids-space-4);
		border-inline-end: 1px solid var(--color-border);
	}

	.tab__placeholder {
		display: flex;
		margin-block-start: var(--ids-space-10);
	}
}
</style>
