<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiRefresh } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	/** What went wrong and what to do */
	text: string
}>()

defineEmits<{
	retry: []
}>()
</script>

<template>
	<NcNoteCard type="error" data-test="load-error">
		<div :class="$style.error">
			<p>{{ text }}</p>
			<NcButton variant="secondary" @click="$emit('retry')">
				<template #icon>
					<NcIconSvgWrapper :path="mdiRefresh" />
				</template>
				{{ t(APP_ID, 'Try again') }}
			</NcButton>
		</div>
	</NcNoteCard>
</template>

<style module>
.error {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.error p {
	margin: 0;
}
</style>
