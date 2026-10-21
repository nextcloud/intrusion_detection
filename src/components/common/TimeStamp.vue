<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import NcDateTime from '@nextcloud/vue/components/NcDateTime'

defineProps<{
	/** Unix time in seconds */
	timestamp: number
	/** The time zone of the absolute time on hover; the browser's by default */
	timeZone?: string
	/** "4 min. ago" instead of "4 minutes ago", for dense rows */
	short?: boolean
}>()
</script>

<template>
	<NcDateTime
		:timestamp="timestamp * 1000"
		:relativeTime="short ? 'short' : 'long'"
		:format="{ dateStyle: 'long', timeStyle: 'short', timeZone }" />
</template>
