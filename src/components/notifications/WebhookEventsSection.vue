<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { WebhookEvents } from '../../types.ts'

import { mdiCheck, mdiContentCopy, mdiWebhook } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onMounted, ref, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SettingsGroup from '../common/SettingsGroup.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { fetchWebhookEvents } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const events = ref<WebhookEvents | null>(null)
const loadFailed = ref(false)
const copied = ref<string | null>(null)
const { announce } = useAnnouncer()

const settings = computed(() => state.settings.filter((s) => s.name === 'events_include_ip'))
const filterExample = JSON.stringify({ 'event.severity': { $in: ['high', 'critical'] } })

/**
 * Load the events with their example payloads.
 */
async function load() {
	try {
		events.value = await fetchWebhookEvents()
		loadFailed.value = false
	} catch (error) {
		logger.error('Could not load the webhook events', { error })
		loadFailed.value = true
	}
}

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

// The examples follow the address setting, so they are loaded again after it was saved.
watch(() => settings.value.map((s) => s.value).join('|'), load)
onMounted(load)
</script>

<template>
	<section :class="$style.card" aria-labelledby="ids-webhooks-heading" data-test="webhook-events-section">
		<div :class="$style.card__header">
			<span :class="$style.card__icon" aria-hidden="true">
				<NcIconSvgWrapper :path="mdiWebhook" />
			</span>
			<div>
				<h3 id="ids-webhooks-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'Webhook events') }}
				</h3>
				<p :class="$style.card__text">
					{{ t(APP_ID, 'Intrusion detection sends three events that the Webhooks app can forward to any address, for example to a chat room, a ticket system or a SIEM. Register a webhook for the event name with the Webhooks API. Events never contain passwords, fingerprints, tokens or other secrets.') }}
				</p>
			</div>
		</div>

		<SettingsGroup v-if="settings.length > 0" :settings="settings" />

		<SkeletonBlock v-if="!events && !loadFailed" height="120px" />
		<NcNoteCard v-else-if="loadFailed" type="error" :text="t(APP_ID, 'The events could not be loaded. Please reload the page.')" />
		<template v-else-if="events">
			<NcNoteCard
				v-if="!events.webhooksEnabled"
				type="info"
				data-test="webhooks-disabled"
				:text="t(APP_ID, 'The Webhooks app (webhook_listeners) is not enabled. Enable it to forward these events.')" />

			<p :class="$style.card__hint">
				{{ t(APP_ID, 'A webhook can filter on the payload. For example, to forward only high and critical detections:') }}
				<code :class="$style.inline">{{ filterExample }}</code>
			</p>

			<div :class="$style.events">
				<details
					v-for="(event, index) in events.events"
					:key="event.class"
					:class="$style.event"
					:open="index === 0"
					data-test="webhook-event">
					<summary :class="$style.event__summary">
						{{ event.name }}
					</summary>
					<div :class="$style.event__body">
						<p :class="$style.event__description">
							{{ event.description }}
						</p>
						<div :class="$style.event__class">
							<code>{{ event.class }}</code>
							<button
								type="button"
								:class="$style.copy"
								:aria-label="t(APP_ID, 'Copy event name {name}', { name: event.class })"
								:title="copied === event.class ? t(APP_ID, 'Copied') : t(APP_ID, 'Copy')"
								@click="copy(event.class)">
								<NcIconSvgWrapper :path="copied === event.class ? mdiCheck : mdiContentCopy" :size="16" />
							</button>
						</div>
						<p :class="$style.event__label">
							{{ t(APP_ID, 'Example payload') }}
						</p>
						<pre
							:class="$style.payload"
							tabindex="0"
							:aria-label="t(APP_ID, 'Example payload of {name}', { name: event.name })"
							data-test="webhook-payload">{{ pretty(event.example) }}</pre>
					</div>
				</details>
			</div>
		</template>
	</section>
</template>

<style module>
.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__header {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: calc(var(--default-grid-baseline) * 10);
	height: calc(var(--default-grid-baseline) * 10);
	border-radius: 50%;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__text {
	margin-block: calc(var(--default-grid-baseline) * 1) 0;
	max-width: 75ch;
	line-height: 1.6;
}

.card__hint {
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
	gap: calc(var(--default-grid-baseline) * 2);
}

.event {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
}

.event__summary {
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	font-weight: 600;
	cursor: pointer;
}

.event__summary:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.event__body {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: 0 calc(var(--default-grid-baseline) * 4) calc(var(--default-grid-baseline) * 4);
	min-width: 0;
}

.event__description {
	margin: 0;
	line-height: 1.5;
}

.event__class {
	display: inline-flex;
	align-self: flex-start;
	align-items: center;
	max-width: 100%;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
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
	min-width: var(--default-clickable-area);
	min-height: var(--default-clickable-area);
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

.event__label {
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	font-weight: 600;
}

.payload {
	margin: 0;
	font-family: monospace;
	padding: calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-dark);
	color: var(--color-main-text);
	font-size: 0.85em;
	line-height: 1.5;
	overflow-x: auto;
	white-space: pre;
}

.payload:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
