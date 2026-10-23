<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'

defineProps<{
	/** An outline icon path (mdi) */
	icon: string
	/** What is empty, e.g. "No decoys yet" */
	name: string
	/** One sentence on what appears here, or what to do */
	description?: string
}>()
</script>

<template>
	<div :class="$style.empty" data-test="empty">
		<span :class="$style.empty__icon" aria-hidden="true">
			<NcIconSvgWrapper inline :path="icon" :size="22" />
		</span>
		<div :class="$style.empty__text">
			<p :class="$style.empty__name">
				{{ name }}
			</p>
			<p v-if="description" :class="$style.empty__description">
				{{ description }}
			</p>
		</div>
	</div>
</template>

<style module>
.empty {
	display: flex;
	align-items: center;
	gap: var(--ids-space-3);
	padding: var(--ids-space-4);
	border: 1px dashed var(--color-border-dark, var(--color-border));
	border-radius: var(--border-radius-large);
}

.empty__icon {
	composes: muted from '../../styles/shared.module.css';
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 44px;
	height: 44px;
	border-radius: 50%;
	background-color: var(--color-background-hover);
}

.empty__text {
	min-width: 0;
}

.empty__name {
	margin: 0;
	font-weight: 600;
}

.empty__description {
	composes: muted from '../../styles/shared.module.css';
	margin: var(--ids-space-half) 0 0;
	max-width: 75ch;
	line-height: 1.5;
}
</style>
