<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentReport, IncidentRequest } from '../types.ts'

import { mdiDownload, mdiFileCodeOutline, mdiFileDocumentAlertOutline, mdiInformationOutline, mdiOpenInNew, mdiPrinterOutline, mdiTextBoxSearchOutline } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, nextTick, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import EmptyNote from '../components/common/EmptyNote.vue'
import SectionCard from '../components/common/SectionCard.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import IncidentForm from '../components/incidents/IncidentForm.vue'
import IncidentSummary from '../components/incidents/IncidentSummary.vue'
import IncidentTimeline from '../components/incidents/IncidentTimeline.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { buildIncidentReport, downloadIncidentReport, errorMessage, isCancelled } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { incidentRequest } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const form = ref<InstanceType<typeof IncidentForm> | null>(null)
const report = ref<IncidentReport | null>(null)
/** The request the shown report was built from; downloads use exactly this one */
const built = ref<IncidentRequest | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
const failed = ref<IncidentRequest | null>(null)
const downloading = ref<'json' | 'html' | 'print' | null>(null)
const { announce } = useAnnouncer()

const subject = computed(() => {
	const value = report.value?.subject
	if (!value) {
		return ''
	}
	if (value.type === 'address') {
		return t(APP_ID, 'Address {address}', { address: value.value })
	}
	return value.displayName && value.displayName !== value.value
		? t(APP_ID, 'Account {account} ({name})', { account: value.value, name: value.displayName })
		: t(APP_ID, 'Account {account}', { account: value.value })
})

/**
 * Build the report and show it.
 *
 * @param request - Subject and period
 */
async function build(request: IncidentRequest) {
	loading.value = true
	error.value = null
	failed.value = null
	try {
		report.value = await buildIncidentReport(request)
		built.value = request
		announce(n(APP_ID, 'The report is ready: %n entry.', 'The report is ready: %n entries.', report.value.entries.length))
	} catch (e) {
		if (isCancelled(e)) {
			return
		}
		logger.error('Could not build the incident report', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The report could not be built. Please try again.'))
		failed.value = request
		announce(error.value)
	} finally {
		loading.value = false
	}
}

/**
 * Offer a file to save.
 *
 * @param blob - The file
 * @param filename - Its name
 */
function save(blob: Blob, filename: string) {
	const url = URL.createObjectURL(blob)
	const link = document.createElement('a')
	link.href = url
	link.download = filename
	document.body.appendChild(link)
	link.click()
	link.remove()
	setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

/**
 * Print the page through a hidden frame. The frame may not run scripts;
 * the document has none and loads nothing.
 *
 * @param html - The printable page
 */
function print(html: string) {
	const frame = document.createElement('iframe')
	frame.setAttribute('sandbox', 'allow-same-origin allow-modals')
	frame.setAttribute('aria-hidden', 'true')
	frame.setAttribute('title', t(APP_ID, 'Incident report'))
	frame.tabIndex = -1
	frame.style.position = 'fixed'
	frame.style.width = '0'
	frame.style.height = '0'
	frame.style.border = '0'
	frame.addEventListener('load', () => {
		const view = frame.contentWindow
		view?.addEventListener('afterprint', () => frame.remove(), { once: true })
		view?.focus()
		view?.print()
	}, { once: true })
	frame.srcdoc = html
	document.body.appendChild(frame)
}

/**
 * Download the report as a file, or print it.
 *
 * @param action - JSON, the HTML page, or print the HTML page
 */
async function download(action: 'json' | 'html' | 'print') {
	if (!built.value) {
		return
	}
	downloading.value = action
	try {
		const { blob, filename } = await downloadIncidentReport(built.value, action === 'json' ? 'json' : 'html')
		if (action === 'print') {
			print(await blob.text())
		} else {
			save(blob, filename)
			announce(t(APP_ID, 'The report was downloaded.'))
		}
	} catch (e) {
		if (isCancelled(e)) {
			return
		}
		logger.error('Could not download the incident report', { error: e })
		showError(errorMessage(e, t(APP_ID, 'The report could not be downloaded. Please try again.')))
	} finally {
		downloading.value = null
	}
}

// "Incident report for this account / address" from a detection: fill the form and build.
watch(incidentRequest, async (request) => {
	if (request === null) {
		return
	}
	incidentRequest.value = null
	await nextTick()
	form.value?.fill(request)
	build(request)
}, { immediate: true, flush: 'post' })
</script>

<template>
	<div :class="$style.tab">
		<SectionCard :heading="t(APP_ID, 'Incident report')" :icon="mdiFileDocumentAlertOutline">
			<template #description>
				{{ t(APP_ID, 'One timeline of everything Nextcloud knows about an account or an address in a period: detections, blocks, app passwords, shares and administration changes. Use it to investigate, and as the basis of a breach notification. Reports are built when you ask for them and never stored; each one is written to the audit log.') }}
			</template>
			<IncidentForm ref="form" :busy="loading" @build="build" />
		</SectionCard>

		<div
			v-if="loading"
			:class="$style.tab__skeleton"
			aria-busy="true"
			:aria-label="t(APP_ID, 'Building the report …')">
			<SkeletonBlock height="28px" width="50%" />
			<SkeletonBlock height="140px" />
			<SkeletonBlock height="64px" />
			<SkeletonBlock height="64px" />
			<SkeletonBlock height="64px" />
		</div>

		<NcNoteCard v-else-if="error" type="error">
			<p>{{ error }}</p>
			<NcButton
				v-if="failed"
				variant="secondary"
				:class="$style.tab__retry"
				@click="build(failed)">
				{{ t(APP_ID, 'Try again') }}
			</NcButton>
		</NcNoteCard>

		<EmptyNote
			v-else-if="report === null"
			:name="t(APP_ID, 'Choose an account or an address')"
			:description="t(APP_ID, 'The report shows what happened, what Nextcloud did, and what is still open. From a detection on the overview, “Incident report” fills this in for you.')"
			:icon="mdiTextBoxSearchOutline" />

		<article v-else :class="$style.report" :aria-label="t(APP_ID, 'Incident report')">
			<header :class="$style.report__head">
				<div :class="$style.report__title">
					<h3 :class="$style.report__subject" data-test="incident-subject">
						{{ subject }}
					</h3>
					<p :class="$style.report__period">
						<NcDateTime :timestamp="report.period.since * 1000" :relativeTime="false" :format="{ dateStyle: 'medium', timeStyle: 'short' }" />
						<span aria-hidden="true">–</span>
						<span class="hidden-visually">{{ t(APP_ID, 'to') }}</span>
						<NcDateTime :timestamp="report.period.until * 1000" :relativeTime="false" :format="{ dateStyle: 'medium', timeStyle: 'short' }" />
					</p>
				</div>
				<div :class="$style.report__actions">
					<NcButton
						variant="secondary"
						:disabled="downloading !== null"
						data-test="incident-download-json"
						@click="download('json')">
						<template #icon>
							<NcLoadingIcon v-if="downloading === 'json'" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiDownload" />
						</template>
						{{ t(APP_ID, 'Download JSON') }}
					</NcButton>
					<NcButton
						variant="secondary"
						:disabled="downloading !== null"
						data-test="incident-print"
						@click="download('print')">
						<template #icon>
							<NcLoadingIcon v-if="downloading === 'print'" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiPrinterOutline" />
						</template>
						{{ t(APP_ID, 'Print or save as PDF') }}
					</NcButton>
					<NcButton
						variant="tertiary"
						:disabled="downloading !== null"
						data-test="incident-download-html"
						@click="download('html')">
						<template #icon>
							<NcLoadingIcon v-if="downloading === 'html'" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiFileCodeOutline" />
						</template>
						{{ t(APP_ID, 'Download page') }}
					</NcButton>
				</div>
			</header>

			<IncidentSummary :summary="report.summary" />

			<NcNoteCard v-if="report.truncated" type="warning" data-test="incident-truncated">
				{{ t(APP_ID, 'Only the first {count} entries of the period are shown. Build reports for shorter periods to see the rest.', { count: report.maxEntries }) }}
			</NcNoteCard>

			<IncidentTimeline :report="report" />

			<section v-if="report.notes.length > 0" :class="$style.report__notes" aria-labelledby="ids-incident-notes">
				<h4 id="ids-incident-notes" :class="$style.report__notesHeading">
					<NcIconSvgWrapper :path="mdiInformationOutline" :size="18" />
					{{ t(APP_ID, 'Not in this report') }}
				</h4>
				<ul :class="$style.report__noteList">
					<li v-for="note in report.notes" :key="note.id">
						{{ note.text }}
						<a
							v-if="note.url"
							:href="note.url"
							target="_blank"
							rel="noreferrer noopener"
							:class="$style.report__link">
							{{ note.linkLabel ?? note.url }}
							<NcIconSvgWrapper :path="mdiOpenInNew" :size="14" inline />
						</a>
					</li>
				</ul>
			</section>
		</article>
	</div>
</template>

<style module>
.tab {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.tab__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.tab__retry {
	margin-block-start: calc(var(--default-grid-baseline) * 2);
}

.report {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	min-width: 0;
}

.report__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.report__title {
	min-width: 0;
}

.report__subject {
	margin: 0;
	font-size: 1.35em;
	font-weight: 700;
	overflow-wrap: anywhere;
}

.report__period {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	color: var(--color-text-maxcontrast);
}

.report__actions {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.report__notes {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.report__notesHeading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	font-size: 0.95em;
	font-weight: 700;
}

.report__noteList {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.5;
}

.report__link {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	color: var(--color-primary-element-text-dark, var(--color-primary-element));
	text-decoration: underline;
}
</style>
