<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check } from '../../types.ts'

import { mdiArrowRightThin, mdiFlaskOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SeverityPill from '../common/SeverityPill.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import { useSimulation } from '../../stores/settings.ts'
import { APP_ID } from '../../utils/format.ts'

const open = defineModel<boolean>('open', { required: true })

const props = defineProps<{
	check: Check
}>()

const { data: result, error, loading, reload } = useSimulation(() => open.value ? props.check.id : null, {
	failure: () => t(APP_ID, 'The simulation did not work. Please try again.'),
})

const mode = computed(() => {
	const current = result.value
	if (current === null) {
		return null
	}
	if (!current.runs) {
		return { type: 'warning' as const, text: t(APP_ID, 'Off'), note: t(APP_ID, 'This check is off, so in reality nothing would be recorded. This is what it would report once it is on.') }
	}
	if (!current.acts) {
		return {
			type: 'info' as const,
			text: current.modeReason === 'learning' ? t(APP_ID, 'Observing while learning') : t(APP_ID, 'Observe'),
			note: current.modeReason === 'learning'
				? t(APP_ID, 'Learning mode is on, so the detection would only be recorded. Once protection starts, these responses run:')
				: t(APP_ID, 'The check is set to Observe, so the detection would only be recorded. In Protect mode these responses run:'),
		}
	}
	return { type: 'success' as const, text: t(APP_ID, 'Protect'), note: null }
})

const buttons = computed(() => [
	{
		label: t(APP_ID, 'Run again'),
		variant: 'secondary' as const,
		disabled: loading.value,
		callback: () => {
			reload()
			return false
		},
	},
	{ label: t(APP_ID, 'Close'), variant: 'primary' as const, callback: () => undefined },
])
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Simulate: {check}', { check: check.texts.name })"
		:buttons="buttons"
		size="normal">
		<div :class="$style.sim" aria-live="polite" :aria-busy="loading ? 'true' : 'false'">
			<p :class="$style.sim__intro">
				<NcIconSvgWrapper inline :path="mdiFlaskOutline" :size="20" />
				<span>{{ t(APP_ID, 'An attack that just reaches your current thresholds, from the test address {address}. Nothing is recorded, blocked or notified.', { address: result?.testAddress ?? '198.51.100.23' }) }}</span>
			</p>

			<NcNoteCard v-if="error" type="error" :text="error" />

			<div v-else-if="loading || result === null" :class="$style.sim__skeleton">
				<SkeletonBlock height="20px" width="60%" />
				<SkeletonBlock height="56px" />
				<SkeletonBlock height="20px" width="40%" />
				<SkeletonBlock height="40px" />
			</div>

			<template v-else>
				<section :class="$style.sim__section" aria-labelledby="ids-sim-report">
					<div :class="$style.sim__head">
						<h3 id="ids-sim-report" :class="$style.sim__heading">
							{{ t(APP_ID, 'What Nextcloud would report') }}
						</h3>
						<SeverityPill :severity="result.severity" />
					</div>
					<blockquote :class="$style.sim__report" data-test="simulation-narrative">
						<p v-for="(sentence, index) in result.narrative.happened" :key="index">
							{{ sentence }}
						</p>
					</blockquote>
				</section>

				<section :class="$style.sim__section" aria-labelledby="ids-sim-done">
					<div :class="$style.sim__head">
						<h3 id="ids-sim-done" :class="$style.sim__heading">
							{{ t(APP_ID, 'What would happen') }}
						</h3>
						<StateBadge v-if="mode" :type="mode.type">
							<span class="hidden-visually">{{ t(APP_ID, 'Mode:') }}</span>
							{{ mode.text }}
						</StateBadge>
					</div>
					<p v-if="mode?.note" :class="$style.sim__note">
						{{ mode.note }}
					</p>
					<ol v-if="result.responses.length > 0" :class="$style.sim__steps" data-test="simulation-responses">
						<li v-for="response in result.responses" :key="response.type">
							<NcIconSvgWrapper inline :path="mdiArrowRightThin" :size="20" />
							<span>{{ response.text }}</span>
						</li>
					</ol>
					<p v-else :class="$style.sim__note">
						{{ t(APP_ID, 'Nothing is done; detections are only recorded.') }}
					</p>
				</section>
			</template>
		</div>
	</NcDialog>
</template>

<style module>
.sim {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-5);
	padding-bottom: var(--ids-space-2);
}

.sim__intro {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	margin: 0;
	padding: var(--ids-space-3);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-info) 10%, var(--color-main-background));
	color: var(--color-main-text);
	line-height: 1.5;
}

.sim__intro > :first-child {
	flex: 0 0 auto;
	color: var(--color-info-text);
}

.sim__skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.sim__section {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.sim__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.sim__heading {
	composes: eyebrow from '../../styles/shared.module.css';
	margin: 0;
}

.sim__report {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	margin: 0;
	padding-block: var(--ids-space-1);
	padding-inline: var(--ids-space-4) 0;
	border-inline-start: 3px solid var(--color-primary-element);
	line-height: 1.6;
}

.sim__report p,
.sim__note {
	margin: 0;
	line-height: 1.6;
}

.sim__note {
	composes: muted from '../../styles/shared.module.css';
}

.sim__steps {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.sim__steps li {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	padding: var(--ids-space-2) var(--ids-space-3);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
	line-height: 1.5;
}

.sim__steps li > :first-child {
	flex: 0 0 auto;
	color: var(--color-primary-element);
}

[dir='rtl'] .sim__steps li > :first-child {
	transform: scaleX(-1);
}
</style>
