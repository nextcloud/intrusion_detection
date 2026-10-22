<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../extensions.ts'

import { mdiChevronDown } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import NcActionButton from '@nextcloud/vue/components/NcActionButton'
import NcActions from '@nextcloud/vue/components/NcActions'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../utils/format.ts'

const active = defineModel<string>({ required: true })

const props = defineProps<{
	tabs: TabDefinition[]
	/** Counts shown next to tab names, by tab id */
	counts?: Record<string, number>
}>()

/** Room for the "More" menu button */
const MORE_WIDTH = 96

const bar = ref<HTMLElement | null>(null)
const measure = ref<HTMLElement | null>(null)
const buttons = ref<HTMLButtonElement[]>([])
/** The width of the bar and of each tab, from the hidden measuring row; 0 until measured */
const available = ref(0)
const widths = ref<number[]>([])

/**
 * The tabs shown in the bar: those that fit, and always the active one.
 * The others are in the "More" menu, so no tab is ever out of reach.
 */
const visible = computed(() => {
	const sizes = widths.value
	if (available.value === 0 || sizes.length !== props.tabs.length || sizes.reduce((sum, width) => sum + width, 0) <= available.value) {
		return props.tabs
	}
	const activeIndex = props.tabs.findIndex((tab) => tab.id === active.value)
	let used = MORE_WIDTH + (sizes[activeIndex] ?? 0)
	const shown: TabDefinition[] = []
	let full = false
	props.tabs.forEach((tab, index) => {
		if (index === activeIndex) {
			shown.push(tab)
		} else if (!full && used + sizes[index]! <= available.value) {
			used += sizes[index]!
			shown.push(tab)
		} else {
			full = true
		}
	})
	return shown
})
const hidden = computed(() => props.tabs.filter((tab) => !visible.value.includes(tab)))

/**
 * Measure the bar and the tabs.
 */
function layout() {
	available.value = bar.value?.clientWidth ?? 0
	widths.value = [...(measure.value?.children ?? [])].map((child) => (child as HTMLElement).offsetWidth)
}

let observer: ResizeObserver | null = null
onMounted(() => {
	layout()
	if (typeof ResizeObserver !== 'undefined' && bar.value) {
		observer = new ResizeObserver(() => layout())
		observer.observe(bar.value)
	}
})
onBeforeUnmount(() => observer?.disconnect())
watch(() => props.tabs.map((tab) => tab.id).join(','), () => nextTick(layout))

/**
 * Arrow keys, Home and End move between all tabs, as in the ARIA tabs
 * pattern; a tab from the "More" menu takes the last place in the bar.
 *
 * @param event - The key event
 * @param id - The focused tab
 */
async function onKeydown(event: KeyboardEvent, id: string) {
	const index = props.tabs.findIndex((tab) => tab.id === id)
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
	const targetId = props.tabs[target]!.id
	active.value = targetId
	await nextTick()
	buttons.value.find((button) => button.dataset.tab === targetId)?.focus()
}

/**
 * @param id - The tab picked in the "More" menu
 */
async function pick(id: string) {
	active.value = id
	await nextTick()
	buttons.value.find((button) => button.dataset.tab === id)?.focus()
}
</script>

<template>
	<div ref="bar" :class="$style.bar">
		<div :class="$style.tabs" role="tablist" :aria-label="t(APP_ID, 'Intrusion detection')">
			<button
				v-for="tab in visible"
				:id="`ids-tab-${tab.id}`"
				ref="buttons"
				:key="tab.id"
				type="button"
				role="tab"
				:data-tab="tab.id"
				:class="[$style.tab, { [$style.tab_active]: tab.id === active }]"
				:aria-selected="tab.id === active ? 'true' : 'false'"
				:aria-controls="`ids-panel-${tab.id}`"
				:tabindex="tab.id === active ? 0 : -1"
				@click="active = tab.id"
				@keydown="onKeydown($event, tab.id)">
				<NcIconSvgWrapper inline :path="tab.icon" :size="20" />
				<span>{{ tab.name() }}</span>
				<span v-if="counts?.[tab.id]" :class="$style.tab__count">
					{{ counts[tab.id] }}
				</span>
			</button>
		</div>

		<NcActions
			v-if="hidden.length > 0"
			:class="$style.more"
			variant="tertiary"
			:menuName="t(APP_ID, 'More')"
			:aria-label="t(APP_ID, 'More tabs')"
			data-test="more-tabs">
			<template #icon>
				<NcIconSvgWrapper :path="mdiChevronDown" :size="20" />
			</template>
			<NcActionButton
				v-for="tab in hidden"
				:key="tab.id"
				closeAfterClick
				@click="pick(tab.id)">
				<template #icon>
					<NcIconSvgWrapper :path="tab.icon" :size="20" />
				</template>
				{{ tab.name() }}{{ counts?.[tab.id] ? ` (${counts[tab.id]})` : '' }}
			</NcActionButton>
		</NcActions>

		<div
			ref="measure"
			:class="[$style.tabs, $style.measure]"
			aria-hidden="true"
			inert>
			<span v-for="tab in tabs" :key="tab.id" :class="$style.tab">
				<NcIconSvgWrapper inline :path="tab.icon" :size="20" />
				<span>{{ tab.name() }}</span>
				<span v-if="counts?.[tab.id]" :class="$style.tab__count">
					{{ counts[tab.id] }}
				</span>
			</span>
		</div>
	</div>
</template>

<style module>
.bar {
	position: relative;
	display: flex;
	align-items: center;
	min-width: 0;
	border-bottom: 1px solid var(--color-border);
}

.tabs {
	display: flex;
	flex: 1 1 auto;
	min-width: 0;
	overflow: hidden;
}

.measure {
	position: absolute;
	inset-inline-start: 0;
	top: 0;
	width: max-content;
	visibility: hidden;
	pointer-events: none;
}

.tabs .tab {
	position: relative;
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	gap: var(--ids-space-2);
	min-height: var(--default-clickable-area);
	margin: 0;
	padding-block: var(--ids-space-2);
	padding-inline: var(--ids-space-3);
	border: none;
	border-radius: var(--border-radius-element) var(--border-radius-element) 0 0;
	background: transparent;
	color: var(--color-text-maxcontrast);
	font-weight: 600;
	white-space: nowrap;
	cursor: pointer;
}

.tabs button.tab:hover {
	background-color: var(--color-background-hover);
	color: var(--color-main-text);
}

.tabs button.tab:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: -2px;
}

.tabs .tab::after {
	content: '';
	position: absolute;
	inset-inline: var(--ids-space-2);
	bottom: 0;
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
	padding-inline: var(--ids-space-1-5);
	border-radius: 10px;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
	font-size: 0.8em;
	line-height: 20px;
	text-align: center;
}

.more {
	flex: 0 0 auto;
}

@media (prefers-reduced-motion: reduce) {
	.tabs .tab::after {
		transition: none;
	}
}
</style>
