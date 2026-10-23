<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { provide } from 'vue'
import NcSettingsSection from '@nextcloud/vue/components/NcSettingsSection'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { personalSections } from '../personal/extensions.ts'
import { useActivity } from '../personal/store.ts'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'

const { message } = useAnnouncer()
provide('ids-flat-sections', true)
useActivity()
</script>

<template>
	<NcSettingsSection
		:name="t(APP_ID, 'Account protection')"
		:description="t(APP_ID, 'What Nextcloud noticed about your account, and what it did about it.')">
		<div :class="$style.sections">
			<div
				v-for="section in personalSections"
				:key="section.id"
				:class="$style.sections__item"
				:data-section="section.id">
				<component :is="section.component" />
			</div>
		</div>

		<div class="hidden-visually" aria-live="polite" aria-atomic="true">
			{{ message }}
		</div>
	</NcSettingsSection>
</template>

<style module>
.sections {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-8);
	max-width: 900px;
}

.sections__item {
	min-width: 0;
}

/* A section that renders nothing takes no room and no gap. */
.sections__item:empty {
	display: none;
}
</style>
