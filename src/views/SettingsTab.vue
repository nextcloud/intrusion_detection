<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import AdvancedTab from './AdvancedTab.vue'
import ConfirmationTab from './ConfirmationTab.vue'
import NotificationsTab from './NotificationsTab.vue'
import PrivacyTab from './PrivacyTab.vue'
</script>

<template>
	<div :class="$style.settings">
		<NotificationsTab />
		<ConfirmationTab />
		<PrivacyTab />
		<AdvancedTab />
	</div>
</template>

<style module>
.settings {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 8);
}
</style>
