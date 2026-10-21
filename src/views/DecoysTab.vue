<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Traps } from '../types.ts'

import { mdiAccountAlertOutline, mdiMapMarkerOutline, mdiTimerSandComplete } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onActivated, onMounted, ref } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import DecoyCredentials from '../components/decoys/DecoyCredentials.vue'
import ReservedNamesCard from '../components/decoys/ReservedNamesCard.vue'
import TrapPathsCard from '../components/decoys/TrapPathsCard.vue'
import { errorMessage, fetchTraps } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshChecks, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const traps = ref<Traps | null>(null)
const loadError = ref<string | null>(null)

const decoysActWhileLearning = computed(() => state.settings.find((s) => s.name === 'learning_decoys_act')?.value === true)
const learning = computed(() => state.status?.learning.active === true)

const steps = [
	{ icon: mdiMapMarkerOutline, title: () => t(APP_ID, 'Plant'), text: () => t(APP_ID, 'Put a fake credential, account name or web address where only an intruder looks.') },
	{ icon: mdiTimerSandComplete, title: () => t(APP_ID, 'Wait'), text: () => t(APP_ID, 'Nobody who belongs here ever uses it, so it costs nothing and does not fire by mistake.') },
	{ icon: mdiAccountAlertOutline, title: () => t(APP_ID, 'Catch'), text: () => t(APP_ID, 'The first use blocks the address at once. No threshold, no waiting for a second try.') },
]

/**
 * Load the decoys, reserved names and trap paths.
 */
async function load() {
	try {
		traps.value = await fetchTraps()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the decoys', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The decoys could not be loaded. Please reload the page.'))
	}
}

onMounted(load)
onActivated(load)

/**
 * The trap lists are also settings of their checks; keep the check cards in step.
 */
function checksChanged() {
	refreshChecks().catch((error) => logger.error('Could not reload the checks', { error }))
}
</script>

<template>
	<div :class="$style.decoys">
		<section :class="$style.how" aria-labelledby="ids-decoys-how">
			<h3 id="ids-decoys-how" :class="$style.how__heading">
				{{ t(APP_ID, 'How decoys work') }}
			</h3>
			<ol :class="$style.how__steps">
				<li v-for="(step, index) in steps" :key="index" :class="$style.step">
					<span :class="$style.step__icon" aria-hidden="true">
						<NcIconSvgWrapper inline :path="step.icon" :size="22" />
					</span>
					<span :class="$style.step__text">
						<strong>{{ step.title() }}</strong>
						<span>{{ step.text() }}</span>
					</span>
				</li>
			</ol>
			<p v-if="learning" :class="$style.how__note">
				{{ decoysActWhileLearning
					? t(APP_ID, 'Decoys act even while Nextcloud is learning, because nobody uses one by accident.')
					: t(APP_ID, 'While Nextcloud is learning, decoys only observe, as you chose on the Advanced tab.') }}
			</p>
		</section>

		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="traps === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 3" :key="i" height="160px" />
		</div>

		<template v-else>
			<DecoyCredentials
				:decoys="traps.decoys"
				:check="traps.decoyCheck"
				:collisions="traps.decoyCollisions"
				@changed="traps.decoys = $event" />
			<ReservedNamesCard
				:reserved="traps.reservedNames"
				:check="traps.reservedCheck"
				@changed="traps.reservedNames = $event; checksChanged()" />
			<TrapPathsCard
				:paths="traps.trapPaths"
				:check="traps.trapCheck"
				@changed="traps.trapPaths = $event; checksChanged()" />
		</template>
	</div>
</template>

<style module>
.decoys {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.how {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid color-mix(in srgb, var(--color-primary-element) 25%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-primary-element) 6%, var(--color-main-background));
}

.how__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.how__steps {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
	gap: calc(var(--default-grid-baseline) * 4);
	margin: 0;
	padding: 0;
	list-style: none;
}

.step {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.step__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 44px;
	height: 44px;
	border-radius: 50%;
	background-color: var(--color-main-background);
	box-shadow: 0 0 0 1px color-mix(in srgb, var(--color-primary-element) 25%, var(--color-border));
	color: var(--color-primary-element);
}

.step__text {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) / 2);
	line-height: 1.5;
}

.how__note {
	margin: 0;
	color: var(--color-text-maxcontrast);
}
</style>
