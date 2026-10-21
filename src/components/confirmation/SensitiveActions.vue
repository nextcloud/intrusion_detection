<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SensitiveActions, SensitiveGroup } from '../../types.ts'

import { mdiAccountKeyOutline, mdiAccountMultipleOutline, mdiCellphoneLink, mdiCogOutline, mdiShareVariantOutline, mdiTwoFactorAuthentication } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SettingsGroup from '../common/SettingsGroup.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, updateSettings } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { globalTypes, globalValues, state } from '../../store.ts'
import { APP_ID, fillTemplateText } from '../../utils/format.ts'

const props = defineProps<{
	sensitive: SensitiveActions
}>()

const emit = defineEmits<{
	/** A group was switched; carries the new groups */
	changed: [groups: SensitiveGroup[]]
}>()

const ICONS: Record<string, string> = {
	account: mdiAccountKeyOutline,
	second_factor: mdiTwoFactorAuthentication,
	devices: mdiCellphoneLink,
	sharing: mdiShareVariantOutline,
	admin: mdiCogOutline,
}

const busy = ref<string | null>(null)
const opts = { escape: false, sanitize: false }
const { announce } = useAnnouncer()

/** Every other setting of the section; the groups are the switches above */
const settings = computed(() => state.settings.filter((s) => s.group === 'sensitive' && s.name !== props.sensitive.setting))

/**
 * @param text - A text with `{setting}` placeholders
 */
function fill(text: string): string {
	return fillTemplateText(text, globalValues.value, globalTypes.value)
}

/**
 * Switch a group of actions on or off.
 *
 * @param group - The group
 * @param on - Whether its actions need confirmation
 */
async function toggle(group: SensitiveGroup, on: boolean) {
	const groups = props.sensitive.groups.map((g) => g.id === group.id ? { ...g, enabled: on } : g)
	busy.value = group.id
	try {
		const payload = await updateSettings({ [props.sensitive.setting]: groups.filter((g) => g.enabled).map((g) => g.id) })
		state.settings = payload.settings
		emit('changed', groups)
		const done = on
			? t(APP_ID, '{group}: protected', { group: group.label }, undefined, opts)
			: t(APP_ID, '{group}: no longer protected', { group: group.label }, undefined, opts)
		showSuccess(done)
		announce(done)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the sensitive actions', { error })
			showError(errorMessage(error, t(APP_ID, 'The change could not be saved. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<div :class="$style.sensitive">
		<ul :class="$style.groups" data-test="sensitive-groups">
			<li
				v-for="group in sensitive.groups"
				:key="group.id"
				:class="[$style.group, { [$style.group_off]: !group.enabled }]"
				:data-group="group.id">
				<div :class="$style.group__head">
					<span :class="$style.group__icon" aria-hidden="true">
						<NcIconSvgWrapper :path="ICONS[group.id] ?? mdiAccountMultipleOutline" :size="20" />
					</span>
					<NcCheckboxRadioSwitch
						type="switch"
						:modelValue="group.enabled"
						:loading="busy === group.id"
						:disabled="busy !== null"
						@update:modelValue="toggle(group, $event)">
						<span :class="$style.group__label">{{ group.label }}</span>
						<span class="hidden-visually">{{ group.enabled ? t(APP_ID, 'protected') : t(APP_ID, 'not protected') }}</span>
					</NcCheckboxRadioSwitch>
				</div>
				<ul :class="$style.group__examples">
					<li v-for="example in group.examples" :key="example">
						{{ fill(example) }}
					</li>
				</ul>
			</li>
		</ul>

		<div :class="$style.risky">
			<h4 :class="$style.risky__heading">
				{{ t(APP_ID, 'A session is risky when') }}
			</h4>
			<ul :class="$style.risky__list">
				<li v-for="reason in sensitive.risky" :key="reason">
					{{ fill(reason) }}
				</li>
			</ul>
		</div>

		<SettingsGroup :settings="settings" />
	</div>
</template>

<style module>
.sensitive {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.groups {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 260px), 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
	padding: 0;
	list-style: none;
}

.group {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
	transition: opacity 150ms ease, background-color 150ms ease;
}

.group_off {
	background-color: var(--color-background-hover);
}

.group_off .group__examples {
	color: var(--color-text-maxcontrast);
}

.group__head {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.group__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text, var(--color-primary-element));
}

.group__label {
	font-weight: 700;
}

.group__examples {
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	font-size: 0.92em;
	line-height: 1.5;
	list-style: disc;
}

.risky {
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.risky__heading {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	font-size: 1em;
	font-weight: 700;
}

.risky__list {
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	line-height: 1.5;
	list-style: disc;
}

@media (prefers-reduced-motion: reduce) {
	.group {
		transition: none;
	}
}
</style>
