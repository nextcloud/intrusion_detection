<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiContentCopy } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { ref } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	reference: string
}>()

const copied = ref(false)
const { announce } = useAnnouncer()

/**
 * Copy the reference, for a reply to the person who was blocked.
 */
async function copy() {
	try {
		await navigator.clipboard.writeText(props.reference)
		copied.value = true
		announce(t(APP_ID, 'Reference {reference} copied', { reference: props.reference }))
		setTimeout(() => {
			copied.value = false
		}, 2000)
	} catch {
		announce(t(APP_ID, 'Could not copy. Select the reference and copy it by hand.'))
	}
}
</script>

<template>
	<span :class="$style.reference">
		<code :class="$style.reference__code">{{ reference }}</code>
		<button
			type="button"
			:class="$style.reference__copy"
			:aria-label="t(APP_ID, 'Copy reference {reference}', { reference })"
			:title="copied ? t(APP_ID, 'Copied') : t(APP_ID, 'Copy')"
			@click="copy">
			<NcIconSvgWrapper :path="copied ? mdiCheck : mdiContentCopy" :size="16" />
		</button>
	</span>
</template>

<style module>
.reference {
	display: inline-flex;
	align-items: center;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	overflow: hidden;
}

.reference__code {
	padding-inline: calc(var(--default-grid-baseline) * 2);
	font-family: var(--font-face-monospace, monospace);
	font-size: 0.9em;
	letter-spacing: 0.04em;
	white-space: nowrap;
}

.reference button.reference__copy {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 28px;
	height: 28px;
	min-height: 28px;
	margin: 0;
	padding: 0;
	border: none;
	border-inline-start: 1px solid var(--color-border);
	border-radius: 0;
	background: transparent;
	color: var(--color-text-maxcontrast);
	cursor: pointer;
}

.reference button.reference__copy > * {
	min-width: 0;
	min-height: 0;
	width: 16px;
	height: 16px;
}

.reference button.reference__copy:hover,
.reference button.reference__copy:focus-visible {
	background-color: var(--color-background-dark);
	color: var(--color-main-text);
}

.reference button.reference__copy:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}
</style>
