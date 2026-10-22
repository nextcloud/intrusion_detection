<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiContentCopy, mdiFileDocumentOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { useCopy } from '../../composables/useCopy.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	/** The text to show and copy */
	content: string
	/** Where it belongs, e.g. /etc/fail2ban/jail.d/nextcloud-ids.local */
	file?: string
	/** What it is, for the copy button's label */
	label: string
}>()

const id = useId()
const { copied, copy } = useCopy()

/**
 * Copy the whole snippet.
 */
function copySnippet() {
	copy(props.content, t(APP_ID, '{label} copied', { label: props.label }))
}
</script>

<template>
	<figure :class="$style.code" :aria-labelledby="`${id}-file`">
		<figcaption :class="$style.code__bar">
			<span :id="`${id}-file`" :class="$style.code__file">
				<NcIconSvgWrapper inline :path="mdiFileDocumentOutline" :size="16" />
				<span>{{ file || label }}</span>
			</span>
			<NcButton
				variant="tertiary"
				size="small"
				:aria-label="t(APP_ID, 'Copy {label}', { label })"
				data-test="copy"
				@click="copySnippet">
				<template #icon>
					<NcIconSvgWrapper :path="copied ? mdiCheck : mdiContentCopy" :size="18" />
				</template>
				{{ copied ? t(APP_ID, 'Copied') : t(APP_ID, 'Copy') }}
			</NcButton>
		</figcaption>
		<pre :class="$style.code__body" tabindex="0" :aria-label="label"><code>{{ content }}</code></pre>
	</figure>
</template>

<style module>
.code {
	display: flex;
	flex-direction: column;
	min-width: 0;
	margin: 0;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
	overflow: hidden;
}

.code__bar {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
	min-height: 40px;
	padding-block: var(--ids-space-1);
	padding-inline: var(--ids-space-3) var(--ids-space-1);
	border-bottom: 1px solid var(--color-border);
}

.code__file {
	composes: muted from '../../styles/shared.module.css';
	display: inline-flex;
	flex: 1 1 auto;
	align-items: center;
	gap: var(--ids-space-2);
	min-width: 0;
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
}

.code__bar > button {
	flex: 0 0 auto;
}

.code__file > span {
	overflow: hidden;
	text-overflow: ellipsis;
	white-space: nowrap;
}

.code__body {
	max-height: 360px;
	margin: 0;
	padding: var(--ids-space-3) var(--ids-space-4);
	overflow: auto;
	background-color: var(--color-main-background);
	color: var(--color-main-text);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
	line-height: 1.6;
	tab-size: 4;
	white-space: pre;
}

.code__body code {
	font-family: inherit;
	font-size: inherit;
}

.code__body:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: -2px;
}
</style>
