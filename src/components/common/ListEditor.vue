<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiAlertCircleOutline, mdiClose, mdiPlus } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import { APP_ID } from '../../utils/format.ts'

const props = withDefaults(defineProps<{
	/** The entries */
	items: string[]
	/** Label of the field that adds an entry */
	label: string
	placeholder?: string
	/** What is wrong with a new entry, in plain words, or null when it is fine */
	validate?: (value: string) => string | null
	/** Turns a typed entry into its stored form, e.g. lower-cased */
	normalise?: (value: string) => string
	/** Entries offered with one click */
	suggestions?: string[]
	/** What the suggestions are */
	suggestionsLabel?: string
	/** Entries with a problem, and what the problem is */
	problems?: Record<string, string>
	/** Shown when there is no entry */
	emptyText?: string
	max?: number
	busy?: boolean
	/** An error from the server about the last change */
	error?: string | null
}>(), {
	placeholder: '',
	validate: () => null,
	normalise: (value: string) => value.trim(),
	suggestions: () => [],
	suggestionsLabel: '',
	problems: () => ({}),
	emptyText: '',
	max: Infinity,
	busy: false,
	error: null,
})

const emit = defineEmits<{
	add: [items: string[]]
	remove: [item: string]
}>()

const id = useId()
const draft = ref('')
const touched = ref(false)

watch(() => props.items, () => {
	if (props.items.includes(props.normalise(draft.value))) {
		draft.value = ''
		touched.value = false
	}
})

const value = computed(() => props.normalise(draft.value))
const draftError = computed(() => {
	if (value.value === '') {
		return null
	}
	if (props.items.includes(value.value)) {
		return t(APP_ID, '"{item}" is in the list already.', { item: value.value }, undefined, { escape: false, sanitize: false })
	}
	if (props.items.length >= props.max) {
		return n(APP_ID, 'The list can have at most %n entry.', 'The list can have at most %n entries.', props.max)
	}
	return props.validate(value.value)
})
const shownError = computed(() => draftError.value ?? (touched.value ? props.error : null))
const canAdd = computed(() => value.value !== '' && draftError.value === null && !props.busy)
const openSuggestions = computed(() => props.suggestions.filter((s) => !props.items.includes(s)))

/**
 * Add the typed entry.
 */
function add() {
	if (!canAdd.value) {
		return
	}
	touched.value = true
	emit('add', [value.value])
}
</script>

<template>
	<div :class="$style.editor">
		<ul v-if="items.length > 0" :class="$style.editor__items" :aria-label="label">
			<li
				v-for="item in items"
				:key="item"
				:class="[$style.chip, { [$style.chip_problem]: problems[item] }]"
				:title="problems[item]">
				<NcIconSvgWrapper
					v-if="problems[item]"
					inline
					:path="mdiAlertCircleOutline"
					:size="16" />
				<code :class="$style.chip__text">{{ item }}</code>
				<span v-if="problems[item]" class="hidden-visually">{{ problems[item] }}</span>
				<button
					type="button"
					:class="$style.chip__remove"
					:disabled="busy"
					:aria-label="t(APP_ID, 'Remove {item}', { item }, undefined, { escape: false, sanitize: false })"
					@click="emit('remove', item)">
					<NcIconSvgWrapper inline :path="mdiClose" :size="16" />
				</button>
			</li>
		</ul>
		<p v-else-if="emptyText" :class="$style.editor__empty">
			{{ emptyText }}
		</p>

		<form :class="$style.editor__add" @submit.prevent="add">
			<NcTextField
				v-model="draft"
				:class="$style.editor__field"
				:label="label"
				:placeholder="placeholder"
				autocomplete="off"
				spellcheck="false"
				:error="shownError !== null"
				:helperText="shownError ?? ''"
				:disabled="busy"
				data-test="list-input"
				@update:modelValue="touched = false" />
			<NcButton
				type="submit"
				variant="secondary"
				:disabled="!canAdd"
				data-test="list-add">
				<template #icon>
					<NcLoadingIcon v-if="busy" />
					<NcIconSvgWrapper v-else :path="mdiPlus" />
				</template>
				{{ t(APP_ID, 'Add') }}
			</NcButton>
		</form>

		<div v-if="openSuggestions.length > 0" :class="$style.editor__suggest">
			<span :id="`${id}-suggest`" :class="$style.editor__suggestLabel">{{ suggestionsLabel || t(APP_ID, 'Suggestions:') }}</span>
			<ul :class="$style.editor__suggestList" :aria-labelledby="`${id}-suggest`">
				<li v-for="suggestion in openSuggestions" :key="suggestion">
					<button
						type="button"
						:class="$style.suggestion"
						:disabled="busy"
						:aria-label="t(APP_ID, 'Add {item}', { item: suggestion }, undefined, { escape: false, sanitize: false })"
						@click="emit('add', [suggestion])">
						<NcIconSvgWrapper inline :path="mdiPlus" :size="16" />
						<code>{{ suggestion }}</code>
					</button>
				</li>
				<li v-if="openSuggestions.length > 1">
					<button
						type="button"
						:class="[$style.suggestion, $style.suggestion_all]"
						:disabled="busy"
						@click="emit('add', openSuggestions)">
						{{ t(APP_ID, 'Add all') }}
					</button>
				</li>
			</ul>
		</div>
	</div>
</template>

<style module>
.editor {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.editor__items {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.chip {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	min-height: 32px;
	padding-inline: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 1);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--color-background-hover);
}

.chip_problem {
	border-color: color-mix(in srgb, var(--color-error) 50%, var(--color-border));
	background-color: color-mix(in srgb, var(--color-error) 10%, var(--color-main-background));
	color: var(--color-error-text);
}

.chip__text {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
	overflow-wrap: anywhere;
}

.chip button.chip__remove {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 24px;
	min-width: 24px;
	height: 24px;
	min-height: 24px;
	margin: 0;
	padding: 0;
	border: none;
	border-radius: 50%;
	background: transparent;
	color: var(--color-text-maxcontrast);
	cursor: pointer;
}

.chip button.chip__remove:hover,
.chip button.chip__remove:focus-visible {
	background-color: var(--color-background-dark);
	color: var(--color-main-text);
}

.chip button.chip__remove:focus-visible {
	outline: 2px solid var(--color-main-text);
}

.editor__empty {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.editor__add {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
}

.editor__field {
	flex: 1 1 220px;
	max-width: 420px;
}

.editor__add > button {
	margin-top: calc(var(--default-grid-baseline) * 1.5);
}

.editor__suggest {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.editor__suggestLabel {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.editor__suggestList {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	padding: 0;
	list-style: none;
}

.editor__suggest button.suggestion {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	min-height: 30px;
	margin: 0;
	padding-block: 0;
	padding-inline: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border: 1px dashed var(--color-border-dark, var(--color-border));
	border-radius: var(--border-radius-pill, 100px);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	cursor: pointer;
}

.editor__suggest button.suggestion:hover,
.editor__suggest button.suggestion:focus-visible {
	border-style: solid;
	border-color: var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.editor__suggest button.suggestion:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

.editor__suggest button.suggestion_all {
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border-style: solid;
	font-weight: 600;
}

.editor__suggest code {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
}
</style>
