<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import ConfirmationSection from '../components/settings/ConfirmationSection.vue'
import LearningSection from '../components/settings/LearningSection.vue'
import NotificationsSection from '../components/settings/NotificationsSection.vue'
import PrivacySection from '../components/settings/PrivacySection.vue'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'

/**
 * The sections of the Settings tab. Their ids are deep-link targets.
 */
const sections = [
	{ id: 'settings-notifications', heading: () => t(APP_ID, 'Notifications'), component: NotificationsSection },
	{ id: 'settings-confirmation', heading: () => t(APP_ID, 'Login confirmation'), component: ConfirmationSection },
	{ id: 'settings-privacy', heading: () => t(APP_ID, 'Data and privacy'), component: PrivacySection },
	{ id: 'settings-learning', heading: () => t(APP_ID, 'Learning mode and other settings'), component: LearningSection },
]
</script>

<template>
	<div :class="$style.settings">
		<section
			v-for="section in sections"
			:id="section.id"
			:key="section.id"
			:class="$style.section"
			:aria-labelledby="`${section.id}-heading`">
			<h3 :id="`${section.id}-heading`" :class="$style.section__heading">
				{{ section.heading() }}
			</h3>
			<component :is="section.component" />
		</section>
	</div>
</template>

<style module>
.settings {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-10);
}

.section {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	scroll-margin-top: var(--ids-space-4);
}

.section__heading {
	margin: 0;
	font-size: 1.25em;
	font-weight: 700;
}
</style>
