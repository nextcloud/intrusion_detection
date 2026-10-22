<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentReport, IncidentRequest } from '../../types.ts'

import { mdiDownload, mdiFileCodeOutline, mdiInformationOutline, mdiOpenInNew, mdiPencilOutline, mdiPrinterOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import TimeStamp from '../common/TimeStamp.vue'
import IncidentSummary from './IncidentSummary.vue'
import IncidentTimeline from './IncidentTimeline.vue'
import { useAction } from '../../composables/useAction.ts'
import { downloadIncidentReport } from '../../services/api.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	report: IncidentReport
	/** The request the report was built from; downloads use exactly this one */
	request: IncidentRequest
}>()

const emit = defineEmits<{
	/** The admin wants another subject or period */
	change: []
}>()

const id = useId()
const heading = ref<HTMLElement | null>(null)
const { busy: downloading, run } = useAction()

const subject = computed(() => {
	const value = props.report.subject
	if (value.type === 'address') {
		return t(APP_ID, 'Address {address}', { address: value.value })
	}
	return value.displayName && value.displayName !== value.value
		? t(APP_ID, 'Account {account} ({name})', { account: value.value, name: value.displayName })
		: t(APP_ID, 'Account {account}', { account: value.value })
})

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
function download(action: 'json' | 'html' | 'print') {
	run(action, async () => {
		const { blob, filename } = await downloadIncidentReport(props.request, action === 'json' ? 'json' : 'html')
		if (action === 'print') {
			print(await blob.text())
		} else {
			save(blob, filename)
		}
	}, {
		done: action === 'print' ? undefined : t(APP_ID, 'The report was downloaded.'),
		fallback: t(APP_ID, 'The report could not be downloaded. Please try again.'),
	})
}

/**
 * Move the focus to the report, e.g. after it was picked from the list.
 */
function focus() {
	heading.value?.focus()
}

defineExpose({ focus })
</script>

<template>
	<article :class="$style.report" :aria-labelledby="`${id}-subject`">
		<header :class="$style.report__head">
			<h3
				:id="`${id}-subject`"
				ref="heading"
				:class="$style.report__subject"
				tabindex="-1"
				data-test="incident-subject">
				{{ subject }}
			</h3>
			<p :class="$style.report__period">
				<TimeStamp :timestamp="report.period.since" />
				<span aria-hidden="true">–</span>
				<span class="hidden-visually">{{ t(APP_ID, 'to') }}</span>
				<TimeStamp :timestamp="report.period.until" />
			</p>
			<div :class="$style.report__actions">
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
					data-test="incident-download-json"
					@click="download('json')">
					<template #icon>
						<NcLoadingIcon v-if="downloading === 'json'" :size="20" />
						<NcIconSvgWrapper v-else :path="mdiDownload" />
					</template>
					{{ t(APP_ID, 'Download JSON') }}
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
				<NcButton variant="tertiary" data-test="incident-change" @click="emit('change')">
					<template #icon>
						<NcIconSvgWrapper :path="mdiPencilOutline" />
					</template>
					{{ t(APP_ID, 'Change period') }}
				</NcButton>
			</div>
		</header>

		<IncidentSummary :summary="report.summary" />

		<NcNoteCard v-if="report.truncated" type="warning" data-test="incident-truncated">
			{{ t(APP_ID, 'Only the first {count} entries of the period are shown. Build reports for shorter periods to see the rest.', { count: report.maxEntries }) }}
		</NcNoteCard>

		<IncidentTimeline :report="report" />

		<section v-if="report.notes.length > 0" :class="$style.report__notes" :aria-labelledby="`${id}-notes`">
			<h4 :id="`${id}-notes`" :class="$style.report__notesHeading">
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
</template>

<style module>
.report {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 6);
	min-width: 0;
}

.report__head {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.report__subject {
	margin: 0;
	font-size: 1.35em;
	font-weight: 700;
	overflow-wrap: anywhere;
	scroll-margin-top: calc(var(--default-grid-baseline) * 4);
}

.report__subject:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
	border-radius: var(--border-radius-element);
}

.report__period {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.report__actions {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1);
	margin-block-start: calc(var(--default-grid-baseline) * 2);
}

.report__notes {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-block-start: calc(var(--default-grid-baseline) * 4);
	border-block-start: 1px solid var(--color-border);
	color: var(--color-text-maxcontrast);
}

.report__notesHeading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	color: var(--color-main-text);
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
