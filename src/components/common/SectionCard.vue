<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { inject, useId } from 'vue'
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
/** Flat sections without a card, as on the personal settings page, which follows core's flat sections */
const flat = inject('ids-flat-sections', false)
</script>

<template>
	<section :class="[$style.card, { [$style.card_flat]: flat }]" :aria-labelledby="id">
		<header :class="$style.card__head">
			<div :class="$style.card__title">
				<span v-if="icon && !flat" :class="$style.card__icon" aria-hidden="true">
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
	gap: var(--ids-space-4);
	min-width: 0;
	padding: var(--ids-space-5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: var(--ids-space-3);
}

.card__title {
	display: flex;
	flex: 1 1 280px;
	align-items: flex-start;
	gap: var(--ids-space-3);
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
	composes: muted from '../../styles/shared.module.css';
	margin: var(--ids-space-1) 0 0;
	max-width: 75ch;
	line-height: 1.5;
}

.card__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
}

.card_flat {
	gap: var(--ids-space-3);
	padding: 0;
	border: none;
	border-radius: 0;
	background-color: transparent;
}

.card_flat .card__heading {
	font-size: 1.05em;
}

@media (max-width: 600px) {
	.card:not(.card_flat) {
		padding: var(--ids-space-3);
	}
}
</style>
