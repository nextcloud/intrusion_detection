<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { GlobalSetting, ParamValue } from '../../types.ts'
import type { Segment } from '../../utils/format.ts'

import { t } from '@nextcloud/l10n'
import { computed, reactive, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import ParamField from '../checks/ParamField.vue'
import ShowMore from './ShowMore.vue'
import { useAction } from '../../composables/useAction.ts'
import { ApiError } from '../../services/api.ts'
import { globalTypes, globalValues, saveSettings } from '../../store.ts'
import { APP_ID, fillTemplate } from '../../utils/format.ts'
import { validateParam } from '../../utils/validate.ts'

const props = defineProps<{
	/** The global settings this group edits */
	settings: GlobalSetting[]
	/** Puts the fields behind a toggle with this label, e.g. "Change the points" */
	collapsedLabel?: string
}>()

defineSlots<{
	/** Shown above the fields; gets the live values for sentences */
	default?: (props: { fill: (template: string) => Segment[], changed: string[] }) => unknown
}>()

const draft = reactive<Record<string, unknown>>({})
const serverErrors = reactive<Record<string, string>>({})
const { busy, run } = useAction()
const saving = computed(() => busy.value !== null)

watch(() => props.settings, (settings, old) => {
	for (const setting of settings) {
		const before = old?.find((s) => s.name === setting.name)
		// Unsaved edits survive when another group saves.
		if (before === undefined || !(setting.name in draft) || JSON.stringify(draft[setting.name]) === JSON.stringify(before.value)) {
			draft[setting.name] = setting.value
		}
	}
}, { immediate: true })

const validation = computed(() => Object.fromEntries(props.settings.map((s) => [s.name, validateParam(s, draft[s.name])])))
const changed = computed(() => props.settings
	.filter((s) => {
		const value = validation.value[s.name]?.value
		return value !== undefined && JSON.stringify(value) !== JSON.stringify(s.value)
	})
	.map((s) => s.name))
const hasErrors = computed(() => props.settings.some((s) => validation.value[s.name]?.error))

const values = computed<Record<string, ParamValue>>(() => ({
	...globalValues.value,
	...Object.fromEntries(props.settings.map((s) => [s.name, validation.value[s.name]?.value ?? s.value])),
}))

/**
 * @param template - A template with `{name}` placeholders
 */
function fill(template: string): Segment[] {
	return fillTemplate(template, values.value, globalTypes.value)
}

/**
 * Save the changed settings.
 */
async function save() {
	if (hasErrors.value || changed.value.length === 0) {
		return
	}
	Object.keys(serverErrors).forEach((key) => delete serverErrors[key])
	await run('save', () => saveSettings(Object.fromEntries(changed.value.map((name) => [name, validation.value[name]!.value!]))), {
		done: t(APP_ID, 'Saved'),
		fallback: t(APP_ID, 'The settings could not be saved. Please try again.'),
		handle: (error) => {
			if (error instanceof ApiError && error.param !== null && props.settings.some((s) => s.name === error.param)) {
				serverErrors[error.param] = error.message
				return true
			}
			return false
		},
	})
}

/**
 * Throw away the unsaved changes.
 */
function discard() {
	for (const setting of props.settings) {
		draft[setting.name] = setting.value
	}
}
</script>

<template>
	<form :class="$style.group" @submit.prevent="save">
		<slot :fill="fill" :changed="changed" />
		<component :is="collapsedLabel ? ShowMore : 'div'" :label="collapsedLabel" data-test="settings-fields">
			<div :class="$style.group__fields">
				<ParamField
					v-for="setting in settings"
					:key="setting.name"
					v-model="draft[setting.name]"
					:param="setting"
					:error="validation[setting.name]?.error ?? serverErrors[setting.name] ?? null"
					:disabled="saving" />
			</div>
		</component>
		<div v-if="changed.length > 0 || hasErrors" :class="$style.group__save">
			<NcButton type="submit" variant="primary" :disabled="hasErrors || saving">
				<template v-if="saving" #icon>
					<NcLoadingIcon />
				</template>
				{{ t(APP_ID, 'Save changes') }}
			</NcButton>
			<NcButton variant="tertiary" :disabled="saving" @click="discard">
				{{ t(APP_ID, 'Discard') }}
			</NcButton>
		</div>
	</form>
</template>

<style module>
.group {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
}

.group__fields {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 240px), 1fr));
	gap: var(--ids-space-4) var(--ids-space-5);
}

.group__save {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}
</style>
