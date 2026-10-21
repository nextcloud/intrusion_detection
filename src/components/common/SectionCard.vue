<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { useId } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'

withDefaults(defineProps<{
	heading: string
	/** An outline icon path (mdi), shown in a soft circle */
	icon?: string
	level?: 'h3' | 'h4'
}>(), {
	icon: undefined,
	level: 'h3',
})

defineSlots<{
	default?: () => unknown
	/** One or two sentences under the heading */
	description?: () => unknown
	/** Buttons and switches on the right of the heading */
	actions?: () => unknown
}>()

const id = useId()
</script>

<template>
	<section :class="$style.card" :aria-labelledby="id">
		<header :class="$style.card__head">
			<div :class="$style.card__title">
				<span v-if="icon" :class="$style.card__icon" aria-hidden="true">
					<NcIconSvgWrapper inline :path="icon" :size="20" />
				</span>
				<div :class="$style.card__titleText">
					<component :is="level" :id="id" :class="$style.card__heading">
						{{ heading }}
					</component>
					<p v-if="$slots.description" :class="$style.card__description">
						<slot name="description" />
					</p>
				</div>
			</div>
			<div v-if="$slots.actions" :class="$style.card__actions">
				<slot name="actions" />
			</div>
		</header>
		<slot />
	</section>
</template>

<style module>
.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__title {
	display: flex;
	flex: 1 1 280px;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	min-width: 0;
}

.card__titleText {
	min-width: 0;
}

.card__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
	line-height: 1.4;
}

.card__description {
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	max-width: 75ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.card__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
