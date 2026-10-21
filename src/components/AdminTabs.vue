<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../extensions.ts'

import { t } from '@nextcloud/l10n'
import { nextTick, ref } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../utils/format.ts'

const active = defineModel<string>({ required: true })

const props = defineProps<{
	tabs: TabDefinition[]
	/** Counts shown next to tab names, by tab id */
	counts?: Record<string, number>
}>()

const buttons = ref<HTMLButtonElement[]>([])

/**
 * Arrow keys, Home and End move between tabs, as in the ARIA tabs pattern.
 *
 * @param event - The key event
 * @param index - The focused tab
 */
async function onKeydown(event: KeyboardEvent, index: number) {
	const last = props.tabs.length - 1
	const rtl = getComputedStyle(event.currentTarget as Element).direction === 'rtl'
	const next = { ArrowRight: rtl ? -1 : 1, ArrowLeft: rtl ? 1 : -1 }[event.key]
	let target: number | undefined
	if (next !== undefined) {
		target = (index + next + props.tabs.length) % props.tabs.length
	} else if (event.key === 'Home') {
		target = 0
	} else if (event.key === 'End') {
		target = last
	}
	if (target === undefined) {
		return
	}
	event.preventDefault()
	active.value = props.tabs[target]!.id
	await nextTick()
	buttons.value[target]?.focus()
}
</script>

<template>
	<div :class="$style.tabs" role="tablist" :aria-label="t(APP_ID, 'Intrusion detection')">
		<button
			v-for="(tab, index) in tabs"
			:id="`ids-tab-${tab.id}`"
			ref="buttons"
			:key="tab.id"
			type="button"
			role="tab"
			:class="[$style.tab, { [$style.tab_active]: tab.id === active }]"
			:aria-selected="tab.id === active ? 'true' : 'false'"
			:aria-controls="`ids-panel-${tab.id}`"
			:tabindex="tab.id === active ? 0 : -1"
			@click="active = tab.id"
			@keydown="onKeydown($event, index)">
			<NcIconSvgWrapper :path="tab.icon" :size="20" />
			<span>{{ tab.name() }}</span>
			<span v-if="counts?.[tab.id]" :class="$style.tab__count">
				{{ counts[tab.id] }}
			</span>
		</button>
	</div>
</template>

<style module>
.tabs {
	display: flex;
	gap: calc(var(--default-grid-baseline) * 1);
	overflow-x: auto;
	border-bottom: 1px solid var(--color-border);
	scrollbar-width: thin;
}

.tabs button.tab {
	position: relative;
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	min-height: var(--default-clickable-area);
	margin: 0;
	padding-block: calc(var(--default-grid-baseline) * 2);
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border: none;
	border-radius: var(--border-radius-element) var(--border-radius-element) 0 0;
	background: transparent;
	color: var(--color-text-maxcontrast);
	font-weight: 600;
	cursor: pointer;
}

.tabs button.tab:hover {
	background-color: var(--color-background-hover);
	color: var(--color-main-text);
}

.tabs button.tab:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.tabs button.tab::after {
	content: '';
	position: absolute;
	inset-inline: calc(var(--default-grid-baseline) * 2);
	bottom: -1px;
	height: 3px;
	border-radius: 3px 3px 0 0;
	background-color: transparent;
	transition: background-color 150ms ease;
}

.tabs button.tab_active {
	color: var(--color-main-text);
}

.tabs button.tab_active::after {
	background-color: var(--color-primary-element);
}

.tab__count {
	min-width: 20px;
	padding-inline: calc(var(--default-grid-baseline) * 1.5);
	border-radius: 10px;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
	font-size: 0.8em;
	line-height: 20px;
	text-align: center;
}

@media (prefers-reduced-motion: reduce) {
	.tabs button.tab::after {
		transition: none;
	}
}
</style>
