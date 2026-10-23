<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { GlobalSetting } from '../../types.ts'
import type { Segment } from '../../utils/format.ts'

import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import ParamField from '../checks/ParamField.vue'
import ShowMore from './ShowMore.vue'
import { useAction } from '../../composables/useAction.ts'
import { useParamDraft } from '../../composables/useParamDraft.ts'
import { saveSettings } from '../../store.ts'
import { APP_ID, fillTemplate } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

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

const { draft, errors, changed, hasErrors, values, types, choices, changes, discard, clearServerErrors, showAtField } = useParamDraft(() => props.settings)
const { busy, run } = useAction()
const saving = computed(() => busy.value !== null)

/**
 * @param template - A template with `{name}` placeholders
 */
function fill(template: string): Segment[] {
	return fillTemplate(template, values.value, types.value, choices.value)
}

/**
 * Save the changed settings.
 */
async function save() {
	if (hasErrors.value || changed.value.length === 0) {
		return
	}
	clearServerErrors()
	await run('save', () => saveSettings(changes()), {
		done: t(APP_ID, 'Saved'),
		fallback: t(APP_ID, 'The settings could not be saved. Please try again.'),
		handle: showAtField,
	})
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
					:error="errors[setting.name] ?? null"
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
