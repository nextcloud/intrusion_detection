<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { t } from '@nextcloud/l10n'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	event: SecurityEvent
}>()
</script>

<template>
	<div :class="$style.details" data-test="details">
		<p v-for="(line, index) in event.happened" :key="`h${index}`">
			{{ line }}
		</p>
		<p :class="$style.details__when">
			{{ event.when }}
		</p>
		<template v-if="event.done.length > 0">
			<h5 :class="$style.details__heading">
				{{ t(APP_ID, 'What Nextcloud did') }}
			</h5>
			<ul :class="$style.details__list">
				<li v-for="(line, index) in event.done" :key="`d${index}`">
					{{ line }}
				</li>
			</ul>
		</template>
		<template v-if="event.advice.length > 0">
			<h5 :class="$style.details__heading">
				{{ t(APP_ID, 'What you can do') }}
			</h5>
			<ul :class="$style.details__list">
				<li v-for="(line, index) in event.advice" :key="`a${index}`">
					{{ line }}
				</li>
			</ul>
		</template>
	</div>
</template>

<style module>
.details {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	max-width: 75ch;
	line-height: 1.5;
}

.details p {
	margin: 0;
}

.details__when {
	composes: muted from '../../styles/shared.module.css';
}

.details__heading {
	margin: var(--ids-space-1) 0 0;
	font-size: 0.95em;
	font-weight: 600;
}

.details__list {
	margin: 0;
	padding-inline-start: var(--ids-space-5);
	list-style: disc;
}
</style>
