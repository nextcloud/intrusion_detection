<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Problem } from '../types.ts'

import { mdiAlertCircleOutline, mdiAlertOutline, mdiChevronDown, mdiInformationOutline, mdiWrenchOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../utils/format.ts'

const props = defineProps<{
	problems: Problem[]
}>()

const id = useId()
const open = ref<string[]>([])

// A single problem starts open; in a list, each title says enough to choose.
watch(() => props.problems.map((p) => p.id).join(','), () => {
	open.value = props.problems.length === 1 ? props.problems.map((p) => p.id) : []
}, { immediate: true })

const LEVELS = {
	error: { icon: mdiAlertCircleOutline, label: () => t(APP_ID, 'Needs action') },
	warning: { icon: mdiAlertOutline, label: () => t(APP_ID, 'Warning') },
	info: { icon: mdiInformationOutline, label: () => t(APP_ID, 'Tip') },
}

const heading = computed(() => n(APP_ID, '%n thing to look at', '%n things to look at', props.problems.length))

/**
 * @param problemId - The problem to open or close
 */
function toggle(problemId: string) {
	open.value = open.value.includes(problemId) ? open.value.filter((p) => p !== problemId) : [...open.value, problemId]
}
</script>

<template>
	<section :class="$style.problems" :aria-labelledby="`${id}-heading`">
		<h3 :id="`${id}-heading`" :class="$style.problems__heading">
			{{ heading }}
		</h3>
		<ul :class="$style.problems__list">
			<li
				v-for="problem in problems"
				:key="problem.id"
				:class="[$style.problem, $style[`problem_${problem.level}`], { [$style.problem_open]: open.includes(problem.id) }]"
				data-test="problem">
				<button
					type="button"
					:class="$style.problem__head"
					:aria-expanded="open.includes(problem.id) ? 'true' : 'false'"
					:aria-controls="`${id}-${problem.id}`"
					@click="toggle(problem.id)">
					<NcIconSvgWrapper
						inline
						:class="$style.problem__icon"
						:path="LEVELS[problem.level].icon"
						:size="20" />
					<span :class="$style.problem__title">{{ problem.title }}</span>
					<span :class="$style.problem__level">{{ LEVELS[problem.level].label() }}</span>
					<NcIconSvgWrapper
						inline
						:class="$style.problem__chevron"
						:path="mdiChevronDown"
						:size="20" />
				</button>
				<div :id="`${id}-${problem.id}`" :class="$style.problem__collapse" :inert="!open.includes(problem.id)">
					<div :class="$style.problem__body">
						<p>{{ problem.text }}</p>
						<p v-if="problem.fix" :class="$style.problem__fix">
							<NcIconSvgWrapper inline :path="mdiWrenchOutline" :size="18" />
							<span><strong>{{ t(APP_ID, 'How to fix it:') }}</strong> {{ problem.fix }}</span>
						</p>
						<p v-if="problem.url">
							<a v-if="problem.url.startsWith('#')" :class="$style.problem__link" :href="problem.url">{{ problem.urlLabel || t(APP_ID, 'Learn more') }}</a>
							<a
								v-else
								:class="$style.problem__link"
								:href="problem.url"
								target="_blank"
								rel="noreferrer noopener">{{ problem.urlLabel || t(APP_ID, 'Learn more') }} ↗</a>
						</p>
					</div>
				</div>
			</li>
		</ul>
	</section>
</template>

<style module>
.problems {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin-top: calc(var(--default-grid-baseline) * 3);
}

.problems__heading {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.problems__list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
	list-style: none;
	overflow: hidden;
}

.problem {
	--problem-color: var(--color-info);
	--problem-text: var(--color-info-text);
	border-top: 1px solid var(--color-border);
	border-inline-start: 4px solid var(--problem-color);
}

.problem:first-child {
	border-top: none;
}

.problem_warning {
	--problem-color: var(--color-warning);
	--problem-text: var(--color-warning-text);
}

.problem_error {
	--problem-color: var(--color-error);
	--problem-text: var(--color-error-text);
}

.problem button.problem__head {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	width: 100%;
	min-height: calc(var(--default-clickable-area) + var(--default-grid-baseline) * 2);
	margin: 0;
	padding-block: calc(var(--default-grid-baseline) * 2);
	padding-inline: calc(var(--default-grid-baseline) * 4) calc(var(--default-grid-baseline) * 3);
	border: none;
	border-radius: 0;
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.problem button.problem__head:hover {
	background-color: var(--color-background-hover);
}

.problem button.problem__head:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.problem__icon {
	flex: 0 0 auto;
	color: var(--problem-text);
}

.problem__title {
	flex: 1 1 auto;
	min-width: 0;
	font-weight: 700;
}

.problem__level {
	flex: 0 0 auto;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-pill, 100px);
	background-color: color-mix(in srgb, var(--problem-color) 14%, var(--color-main-background));
	color: var(--problem-text);
	font-size: 0.8em;
	font-weight: 600;
	line-height: 1.8;
	white-space: nowrap;
}

.problem__chevron {
	flex: 0 0 auto;
	width: 20px;
	min-width: 20px;
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.problem_open .problem__chevron {
	transform: rotate(180deg);
}

.problem__collapse {
	display: grid;
	grid-template-rows: 0fr;
	opacity: 0;
	transition: grid-template-rows 180ms ease, opacity 180ms ease;
}

.problem_open .problem__collapse {
	grid-template-rows: 1fr;
	opacity: 1;
}

.problem__body {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	min-height: 0;
	overflow: hidden;
	padding-inline: calc(var(--default-grid-baseline) * 12) calc(var(--default-grid-baseline) * 4);
}

.problem_open .problem__body {
	padding-bottom: calc(var(--default-grid-baseline) * 4);
}

.problem__body p {
	margin: 0;
	max-width: 90ch;
	line-height: 1.55;
}

.problem__fix {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
}

.problem__fix > :first-child {
	flex: 0 0 auto;
	margin-top: 2px;
	color: var(--color-text-maxcontrast);
}

.problem__link {
	font-weight: 600;
	text-decoration: underline;
	text-underline-offset: 3px;
}

@media (max-width: 600px) {
	.problem__body {
		padding-inline: calc(var(--default-grid-baseline) * 4);
	}

	.problem__level {
		display: none;
	}
}

@media (prefers-reduced-motion: reduce) {
	.problem__chevron,
	.problem__collapse {
		transition: none;
	}
}
</style>
