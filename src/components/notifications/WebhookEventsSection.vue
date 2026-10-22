<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiContentCopy, mdiWebhook } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import CodeBlock from '../common/CodeBlock.vue'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { state } from '../../store.ts'
import { useWebhookEvents } from '../../stores/settings.ts'
import { APP_ID } from '../../utils/format.ts'

const { data: events, error } = useWebhookEvents()
const loadFailed = computed(() => error.value !== null)
const copied = ref<string | null>(null)
const { announce } = useAnnouncer()

const settings = computed(() => state.settings.filter((s) => s.name === 'events_include_ip'))
const filterExample = JSON.stringify({ 'event.severity': { $in: ['high', 'critical'] } })

/**
 * @param value - The example payload
 */
function pretty(value: unknown): string {
	return JSON.stringify(value, null, 2)
}

/**
 * Copy an event class name, for registering a webhook.
 *
 * @param className - The PHP class of the event
 */
async function copy(className: string) {
	try {
		await navigator.clipboard.writeText(className)
		copied.value = className
		announce(t(APP_ID, 'Event name copied'))
		setTimeout(() => {
			copied.value = null
		}, 2000)
	} catch {
		announce(t(APP_ID, 'Could not copy. Select the event name and copy it by hand.'))
	}
}
</script>

<template>
	<SectionCard
		level="h4"
		:heading="t(APP_ID, 'Webhook events')"
		:icon="mdiWebhook"
		data-test="webhook-events-section">
		<template #description>
			{{ t(APP_ID, 'The Webhooks app can forward these events to a chat room, a ticket system or a SIEM. They never contain passwords, tokens or other secrets.') }}
		</template>

		<SettingsGroup v-if="settings.length > 0" :settings="settings" />

		<SkeletonBlock v-if="!events && !loadFailed" height="120px" />
		<NcNoteCard v-else-if="loadFailed" type="error" :text="t(APP_ID, 'The events could not be loaded. Please reload the page.')" />
		<template v-else-if="events">
			<NcNoteCard
				v-if="!events.webhooksEnabled"
				type="info"
				data-test="webhooks-disabled"
				:text="t(APP_ID, 'The Webhooks app (webhook_listeners) is not enabled. Enable it to forward these events.')" />

			<ul :class="$style.events">
				<li
					v-for="event in events.events"
					:key="event.class"
					:class="$style.event"
					data-test="webhook-event">
					<div :class="$style.event__head">
						<strong>{{ event.name }}</strong>
						<span :class="$style.event__class">
							<code>{{ event.class }}</code>
							<button
								type="button"
								:class="$style.copy"
								:aria-label="t(APP_ID, 'Copy event name {name}', { name: event.class })"
								:title="copied === event.class ? t(APP_ID, 'Copied') : t(APP_ID, 'Copy')"
								@click="copy(event.class)">
								<NcIconSvgWrapper inline :path="copied === event.class ? mdiCheck : mdiContentCopy" :size="16" />
							</button>
						</span>
					</div>
					<p :class="$style.event__description">
						{{ event.description }}
					</p>
					<ShowMore :label="t(APP_ID, 'Show the example payload')" data-test="webhook-payload-toggle">
						<CodeBlock
							:content="pretty(event.example)"
							:label="t(APP_ID, 'Example payload of {name}', { name: event.name })"
							data-test="webhook-payload" />
					</ShowMore>
				</li>
			</ul>

			<p :class="$style.hint">
				{{ t(APP_ID, 'A webhook can filter on the payload, for example to forward only high and critical detections:') }}
				<code :class="$style.inline">{{ filterExample }}</code>
			</p>
		</template>
	</SectionCard>
</template>

<style module>
.hint {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.6;
}

.inline {
	padding-inline: calc(var(--default-grid-baseline) * 1);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	color: var(--color-main-text);
	overflow-wrap: anywhere;
}

.events {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	list-style: none;
}

.event {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
}

.event + .event {
	border-top: 1px solid var(--color-border);
}

.event__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.event__description {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.event__class {
	display: inline-flex;
	align-items: center;
	max-width: 100%;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-size: 0.85em;
	overflow: hidden;
}

.event__class code {
	padding-inline: calc(var(--default-grid-baseline) * 2);
	overflow-wrap: anywhere;
}

.event__class button.copy {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	min-width: 34px;
	min-height: 34px;
	margin: 0;
	padding: 0;
	border: none;
	border-inline-start: 1px solid var(--color-border);
	border-radius: 0;
	background: transparent;
	color: var(--color-main-text);
	cursor: pointer;
}

.event__class button.copy:hover {
	background-color: var(--color-background-dark);
}

.event__class button.copy:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}
</style>
