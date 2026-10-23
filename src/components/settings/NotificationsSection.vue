<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { generateUrl } from '@nextcloud/router'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import CheckNotifications from '../notifications/CheckNotifications.vue'
import DigestSection from '../notifications/DigestSection.vue'
import NotificationRecipients from '../notifications/NotificationRecipients.vue'
import WebhookEventsSection from '../notifications/WebhookEventsSection.vue'
import { useNotifications } from '../../stores/settings.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

const { data, error: loadError } = useNotifications({ failure: () => t(APP_ID, 'The notification settings could not be loaded. Please reload the page.') })
const mailSettingsUrl = generateUrl('/settings/admin/server')
</script>

<template>
	<div :class="$style.stack">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 3" :key="i" height="140px" />
		</div>

		<template v-else>
			<NcNoteCard v-if="!data.mail" type="warning" data-test="no-mail">
				{{ t(APP_ID, 'This server cannot send emails yet, so alerts and digests appear only inside Nextcloud.') }}
				<a :href="mailSettingsUrl" :class="$style.link">{{ t(APP_ID, 'Set up the email server') }}</a>
			</NcNoteCard>

			<NotificationRecipients :data="data" />

			<DigestSection />

			<CheckNotifications :checks="data.checks" />

			<WebhookEventsSection />
		</template>
	</div>
</template>

<style module>
.stack {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.link {
	color: var(--color-main-text);
	font-weight: 600;
	text-decoration: underline;
	text-decoration-color: var(--color-border-dark, var(--color-border));
	text-underline-offset: 3px;
}

.link:hover,
.link:focus-visible {
	text-decoration-color: currentColor;
}
</style>
