<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '@nextcloud/l10n'
import { computed, provide } from 'vue'
import NcSettingsSection from '@nextcloud/vue/components/NcSettingsSection'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { orderedPersonalSections } from '../personal/extensions.ts'
import { APP_ID } from '../utils/format.ts'

const { message } = useAnnouncer()
const sections = computed(() => orderedPersonalSections())
provide('ids-flat-sections', true)
</script>

<template>
	<NcSettingsSection
		:name="t(APP_ID, 'Account protection')"
		:description="t(APP_ID, 'What Nextcloud noticed about your account, and what it did about it.')">
		<div :class="$style.container">
			<div :class="$style.sections">
				<div
					v-for="section in sections"
					:key="section.id"
					:class="[$style.sections__item, { [$style.sections__item_half]: section.width === 'half' }]"
					:data-section="section.id">
					<component :is="section.component" />
				</div>
			</div>
		</div>

		<div class="hidden-visually" aria-live="polite" aria-atomic="true">
			{{ message }}
		</div>
	</NcSettingsSection>
</template>

<style module>
.container {
	container-type: inline-size;
	max-width: 900px;
}

.sections {
	display: grid;
	grid-template-columns: repeat(2, minmax(0, 1fr));
	gap: calc(var(--default-grid-baseline) * 8) calc(var(--default-grid-baseline) * 8);
}

.sections__item {
	grid-column: 1 / -1;
	min-width: 0;
}

/* A section that renders nothing takes no room and no gap. */
.sections__item:empty {
	display: none;
}

.sections__item_half {
	grid-column: auto;
}

@container (max-width: 640px) {
	.sections {
		grid-template-columns: minmax(0, 1fr);
	}

	.sections__item_half {
		grid-column: 1 / -1;
	}
}
</style>
