/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.services.scheduled;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tag;
import org.keycloak.Config;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.utils.KeycloakModelUtils;

import org.jboss.logging.Logger;

/**
 * Scheduled task for automatic key rotation.
 */
public class AutomaticKeyRotationTask implements ScheduledTask {

    private static final Logger logger = Logger.getLogger(AutomaticKeyRotationTask.class);

    public static final String TASK_NAME = "AutomaticKeyRotation";

    private static final String KEY_ROTATION_METER_NAME = "keycloak.key.rotation";
    private static final Meter.MeterProvider<Counter> rotationMeterProvider = Counter.builder(KEY_ROTATION_METER_NAME)
            .description("Key rotation operations")
            .baseUnit("operations")
            .withRegistry(Metrics.globalRegistry);

    private static final String KEY_LAST_ROTATED_METER_NAME = "keycloak.key.last_rotated_seconds";

    private static final Map<String, AtomicLong> rotationGaugeValues = new ConcurrentHashMap<>();

    private static final String AUTO_ROTATION_ENABLED_KEY = "autoRotationEnabled";
    private static final String ROTATION_PERIOD_KEY = "rotationPeriod";
    private static final String LAST_ROTATION_TIME_KEY = "lastRotationTime";
    private static final String ACTIVE_KEY = "active";
    private static final String ENABLED_KEY = "enabled";
    private static final String KEY_USE = "keyUse";
    private static final String ALGORITHM_KEY = "algorithm";
    private static final String KEY_SIZE_KEY = "keySize";
    private static final String PASSIVE_KEY_EXPIRATION_KEY = "passiveKeyExpiration";
    private static final String AUTO_DELETE_DISABLED_KEYS_KEY = "autoDeleteDisabledKeys";
    private static final String DELETION_GRACE_PERIOD_KEY = "deletionGracePeriod";
    private static final String DISABLED_TIME_KEY = "disabledTime";

    /**
     * Immutable DTO representing provider rotation state - single source of truth per iteration.
     */
    private record ProviderRotationState(
            String realmId,
            String realmName,
            String providerId,
            String providerName,
            String providerType,
            Long lastRotationTimeMillis,
            long rotationPeriodSeconds,
            long passiveExpirationSeconds,
            boolean autoRotationEnabled,
            boolean active,
            boolean enabled,
            Long disabledTimeMillis,
            boolean autoDeleteEnabled,
            long deletionGracePeriodSeconds
    ) {
        static ProviderRotationState from(ComponentModel c, RealmModel r) {
            Long lastRotation = parseLongOrNull(c.get(LAST_ROTATION_TIME_KEY));
            Long disabledTime = parseLongOrNull(c.get(DISABLED_TIME_KEY));
            long rotationPeriod = parseLongOrDefault(c.get(ROTATION_PERIOD_KEY), 7776000L);
            long passiveExp = parseLongOrDefault(c.get(PASSIVE_KEY_EXPIRATION_KEY), 0L);
            long gracePeriod = parseLongOrDefault(c.get(DELETION_GRACE_PERIOD_KEY), 3600L);

            return new ProviderRotationState(
                    r.getId(),
                    r.getName(),
                    c.getId(),
                    c.getName(),
                    c.getProviderId(),
                    lastRotation,
                    rotationPeriod,
                    passiveExp,
                    "true".equalsIgnoreCase(c.get(AUTO_ROTATION_ENABLED_KEY)),
                    !"false".equalsIgnoreCase(c.get(ACTIVE_KEY)),
                    !"false".equalsIgnoreCase(c.get(ENABLED_KEY)),
                    disabledTime,
                    "true".equalsIgnoreCase(c.get(AUTO_DELETE_DISABLED_KEYS_KEY)),
                    gracePeriod
            );
        }

        private static Long parseLongOrNull(String val) {
            if (val == null || val.trim().isEmpty()) return null;
            try { return Long.parseLong(val); } catch (NumberFormatException e) { return null; }
        }

        private static long parseLongOrDefault(String val, long def) {
            Long parsed = parseLongOrNull(val);
            return parsed != null ? parsed : def;
        }
    }

    @Override
    public void run(KeycloakSession session) {
        long now = Time.currentTimeMillis();
        long start = now;

        int rotatedKeysCount = 0;
        int expiredKeysCount = 0;
        int deletedKeysCount = 0;
        int autoRotationEnabledCount = 0;

        KeycloakSessionFactory factory = session.getKeycloakSessionFactory();

        for (RealmModel realm : session.realms().getRealmsStream().toList()) {
            try {
                initializeMissingRotationTimestamps(factory, realm);

                List<ProviderRotationState> snapshots = realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                        .map(c -> ProviderRotationState.from(c, realm))
                        .toList();

                snapshots.forEach(this::publishLastRotationGauge);

                for (ProviderRotationState s : snapshots) {
                    try {
                        if (s.autoRotationEnabled()) {
                            autoRotationEnabledCount++;
                        }

                        if (s.autoRotationEnabled() && isDueForRotation(s, now)) {
                            rotateKeyTx(factory, s);
                            rotatedKeysCount++;
                        }

                        if (!s.active() && shouldExpire(s, now, realm)) {
                            expirePassiveKeyTx(factory, s);
                            expiredKeysCount++;
                        }

                        if (shouldDelete(s, now)) {
                            deleteDisabledKeyTx(factory, s);
                            deletedKeysCount++;
                        }
                    } catch (Exception e) {
                        logger.errorv(e, "Failed to process key '%s' in realm '%s'", s.providerName(), s.realmName());
                    }
                }
            } catch (Exception e) {
                logger.errorv(e, "Automatic key rotation failed for realm '%s'", realm.getName());
            }
        }

        long durationMillis = Time.currentTimeMillis() - start;
        long intervalSeconds = Config.scope("scheduled").getLong("interval", 900L);

        if (autoRotationEnabledCount > 0 || rotatedKeysCount > 0 || expiredKeysCount > 0 || deletedKeysCount > 0) {
            logger.infof("Automatic key rotation task: %d providers with auto-rotation enabled, rotated=%d, expired=%d, deleted=%d keys in %d ms, next run in %d seconds",
                    autoRotationEnabledCount, rotatedKeysCount, expiredKeysCount, deletedKeysCount, durationMillis, intervalSeconds);
        }
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    private void initializeMissingRotationTimestamps(KeycloakSessionFactory factory, RealmModel realm) {
        realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .filter(c -> "true".equalsIgnoreCase(c.get(AUTO_ROTATION_ENABLED_KEY)))
                .filter(c -> !c.contains(LAST_ROTATION_TIME_KEY) || c.get(LAST_ROTATION_TIME_KEY) == null || c.get(LAST_ROTATION_TIME_KEY).trim().isEmpty())
                .forEach(c -> KeycloakModelUtils.runJobInTransaction(factory, txSession -> {
                    RealmModel txRealm = txSession.realms().getRealm(realm.getId());
                    ComponentModel fresh = txRealm.getComponent(c.getId());
                    if (fresh == null || (fresh.contains(LAST_ROTATION_TIME_KEY) && fresh.get(LAST_ROTATION_TIME_KEY) != null && !fresh.get(LAST_ROTATION_TIME_KEY).trim().isEmpty())) {
                        return;
                    }
                    MultivaluedHashMap<String, String> cfg = new MultivaluedHashMap<>(fresh.getConfig());
                    cfg.putSingle(LAST_ROTATION_TIME_KEY, String.valueOf(Time.currentTimeMillis()));
                    fresh.setConfig(cfg);
                    txRealm.updateComponent(fresh);
                }));
    }

    private void publishLastRotationGauge(ProviderRotationState s) {
        try {
            String gaugeKey = s.realmId() + ":" + s.providerId();

            if (!s.active()) {
                AtomicLong removed = rotationGaugeValues.remove(gaugeKey);
                if (removed != null) {
                    Metrics.globalRegistry.remove(Metrics.globalRegistry.find(KEY_LAST_ROTATED_METER_NAME)
                            .tag("realm", s.realmName())
                            .tag("provider", s.providerType())
                            .tag("name", s.providerName())
                            .meter());
                }
                return;
            }

            if (s.lastRotationTimeMillis() == null) {
                return;
            }

            long lastRotationTimeSeconds = s.lastRotationTimeMillis() / 1000;

            AtomicLong gaugeValue = rotationGaugeValues.computeIfAbsent(gaugeKey, k -> {
                AtomicLong value = new AtomicLong(lastRotationTimeSeconds);
                List<Tag> tags = List.of(
                        Tag.of("realm", s.realmName()),
                        Tag.of("provider", s.providerType()),
                        Tag.of("name", s.providerName())
                );
                Gauge.builder(KEY_LAST_ROTATED_METER_NAME, value, AtomicLong::get)
                        .description("Unix timestamp (seconds) when key was last rotated")
                        .tags(tags)
                        .register(Metrics.globalRegistry);
                return value;
            });

            gaugeValue.set(lastRotationTimeSeconds);
        } catch (Exception e) {
            logger.infov(e, "Failed to update rotation metric for provider '%s'", s.providerName());
        }
    }

    private boolean isDueForRotation(ProviderRotationState s, long now) {
        if (!s.autoRotationEnabled() || !s.active()) {
            return false;
        }
        if (s.lastRotationTimeMillis() == null) {
            return false;
        }
        long elapsedMs = now - s.lastRotationTimeMillis();
        long rotationPeriodMs = java.util.concurrent.TimeUnit.SECONDS.toMillis(s.rotationPeriodSeconds());
        return elapsedMs >= rotationPeriodMs;
    }

    private boolean shouldExpire(ProviderRotationState s, long now, RealmModel realm) {
        if (s.active()) {
            return false;
        }

        long minimumRetentionSeconds = computeMinimumPassiveKeyRetention(realm);
        long passiveExpirationSeconds;

        if (s.passiveExpirationSeconds() > 0) {
            if (s.passiveExpirationSeconds() < minimumRetentionSeconds) {
                logger.warnf("Configured passive key expiration (%d s) for provider '%s' in realm '%s' " +
                                "is shorter than minimum (%d s). Using minimum.",
                        s.passiveExpirationSeconds(), s.providerName(), s.realmName(), minimumRetentionSeconds);
            }
            passiveExpirationSeconds = Math.max(s.passiveExpirationSeconds(), minimumRetentionSeconds);
        } else {
            passiveExpirationSeconds = minimumRetentionSeconds;
        }

        if (s.lastRotationTimeMillis() == null) {
            return false;
        }

        long passiveExpirationMs = java.util.concurrent.TimeUnit.SECONDS.toMillis(passiveExpirationSeconds);
        return (now - s.lastRotationTimeMillis()) >= passiveExpirationMs;
    }

    private boolean shouldDelete(ProviderRotationState s, long now) {
        if (!s.autoDeleteEnabled() || s.enabled()) {
            return false;
        }

        if (s.disabledTimeMillis() == null) {
            return false;
        }

        long gracePeriodMs = java.util.concurrent.TimeUnit.SECONDS.toMillis(s.deletionGracePeriodSeconds());
        return (now - s.disabledTimeMillis()) >= gracePeriodMs;
    }

    static long computeMinimumPassiveKeyRetention(RealmModel realm) {
        long maxLifespanSeconds = 0;

        maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getSsoSessionMaxLifespan());
        maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getSsoSessionIdleTimeout());

        if (realm.getSsoSessionMaxLifespanRememberMe() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getSsoSessionMaxLifespanRememberMe());
        }
        if (realm.getSsoSessionIdleTimeoutRememberMe() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getSsoSessionIdleTimeoutRememberMe());
        }

        maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getOfflineSessionIdleTimeout());

        if (realm.isOfflineSessionMaxLifespanEnabled()) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getOfflineSessionMaxLifespan());
        }

        if (realm.getClientOfflineSessionIdleTimeout() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getClientOfflineSessionIdleTimeout());
        }
        if (realm.getClientOfflineSessionMaxLifespan() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getClientOfflineSessionMaxLifespan());
        }
        if (realm.getClientSessionIdleTimeout() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getClientSessionIdleTimeout());
        }
        if (realm.getClientSessionMaxLifespan() > 0) {
            maxLifespanSeconds = Math.max(maxLifespanSeconds, realm.getClientSessionMaxLifespan());
        }

        long safetyMarginSeconds = Math.max(3600L, maxLifespanSeconds / 10);
        return maxLifespanSeconds + safetyMarginSeconds;
    }

    private void rotateKeyTx(KeycloakSessionFactory factory, ProviderRotationState s) {
        KeycloakModelUtils.runJobInTransaction(factory, txSession -> {
            RealmModel realm = txSession.realms().getRealm(s.realmId());
            if (realm == null) return;

            ComponentModel current = realm.getComponent(s.providerId());
            if (current == null) return;

            long currentTime = Time.currentTimeMillis();

            MultivaluedHashMap<String, String> currentConfig = new MultivaluedHashMap<>(current.getConfig());
            currentConfig.putSingle(ACTIVE_KEY, "false");
            currentConfig.putSingle(LAST_ROTATION_TIME_KEY, String.valueOf(currentTime));
            current.setConfig(currentConfig);
            realm.updateComponent(current);

            ComponentModel newProvider = new ComponentModel();
            String baseName = current.getProviderId();
            newProvider.setName(baseName + "-" + currentTime);
            newProvider.setParentId(realm.getId());
            newProvider.setProviderId(current.getProviderId());
            newProvider.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            long currentPriority = current.get("priority", 0L);
            config.putSingle("priority", String.valueOf(currentPriority + 1));

            if (current.contains(KEY_USE)) config.putSingle(KEY_USE, current.get(KEY_USE));
            if (current.contains(ALGORITHM_KEY)) config.putSingle(ALGORITHM_KEY, current.get(ALGORITHM_KEY));
            if (current.contains(KEY_SIZE_KEY)) config.putSingle(KEY_SIZE_KEY, current.get(KEY_SIZE_KEY));

            newProvider.setConfig(config);
            ComponentModel added = realm.addComponentModel(newProvider);

            MultivaluedHashMap<String, String> rotationConfig = new MultivaluedHashMap<>(added.getConfig());
            rotationConfig.putSingle(AUTO_ROTATION_ENABLED_KEY, "true");
            rotationConfig.putSingle(ROTATION_PERIOD_KEY, String.valueOf(s.rotationPeriodSeconds()));
            rotationConfig.putSingle(PASSIVE_KEY_EXPIRATION_KEY, String.valueOf(s.passiveExpirationSeconds()));
            rotationConfig.putSingle(LAST_ROTATION_TIME_KEY, String.valueOf(currentTime));
            rotationConfig.putSingle(ACTIVE_KEY, "true");
            rotationConfig.putSingle(ENABLED_KEY, "true");
            rotationConfig.putSingle(AUTO_DELETE_DISABLED_KEYS_KEY, String.valueOf(s.autoDeleteEnabled()));
            rotationConfig.putSingle(DELETION_GRACE_PERIOD_KEY, String.valueOf(s.deletionGracePeriodSeconds()));
            added.setConfig(rotationConfig);
            realm.updateComponent(added);

            List<Tag> tags = List.of(
                    Tag.of("realm", s.realmName()),
                    Tag.of("provider", s.providerType()),
                    Tag.of("operation", "rotate")
            );
            rotationMeterProvider.withTags(tags).increment();

            logger.infof("Automatic key rotation activated: Created new key provider '%s' (id=%s) for realm '%s'",
                    added.getName(), added.getId(), s.realmName());

            publishLastRotationGauge(ProviderRotationState.from(added, realm));
            fireAdminEvent(txSession, realm, added, OperationType.CREATE, "Automatic key rotation activated");
        });
    }

    private void expirePassiveKeyTx(KeycloakSessionFactory factory, ProviderRotationState s) {
        KeycloakModelUtils.runJobInTransaction(factory, txSession -> {
            RealmModel realm = txSession.realms().getRealm(s.realmId());
            if (realm == null) return;

            ComponentModel provider = realm.getComponent(s.providerId());
            if (provider == null) return;

            String enabledStr = provider.get(ENABLED_KEY);
            boolean wasEnabled = enabledStr == null || !"false".equalsIgnoreCase(enabledStr);
            if (!wasEnabled) return;

            long currentTime = Time.currentTimeMillis();

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>(provider.getConfig());
            config.putSingle(ENABLED_KEY, "false");
            config.putSingle(DISABLED_TIME_KEY, String.valueOf(currentTime));
            provider.setConfig(config);
            realm.updateComponent(provider);

            List<Tag> tags = List.of(
                    Tag.of("realm", s.realmName()),
                    Tag.of("provider", s.providerType()),
                    Tag.of("operation", "expire")
            );
            rotationMeterProvider.withTags(tags).increment();

            logger.infof("Disabled expired passive key provider '%s' in realm '%s' at %d",
                    s.providerName(), s.realmName(), currentTime);

            fireAdminEvent(txSession, realm, provider, OperationType.UPDATE, "Automatic expiration of passive key");
        });
    }

    private void deleteDisabledKeyTx(KeycloakSessionFactory factory, ProviderRotationState s) {
        KeycloakModelUtils.runJobInTransaction(factory, txSession -> {
            RealmModel realm = txSession.realms().getRealm(s.realmId());
            if (realm == null) return;

            ComponentModel provider = realm.getComponent(s.providerId());
            if (provider == null) return;

            logger.infof("Automatic key deletion: provider='%s', realm='%s', providerId='%s', gracePeriod=%d seconds",
                    s.providerName(), s.realmName(), s.providerId(), s.deletionGracePeriodSeconds());

            fireAdminEvent(txSession, realm, provider, OperationType.DELETE,
                    "Automatic deletion of disabled key after grace period");

            realm.removeComponent(provider);

            List<Tag> tags = List.of(
                    Tag.of("realm", s.realmName()),
                    Tag.of("provider", s.providerType()),
                    Tag.of("operation", "delete")
            );
            rotationMeterProvider.withTags(tags).increment();
        });
    }

    private void fireAdminEvent(KeycloakSession session, RealmModel realm, ComponentModel component,
                                OperationType operationType, String message) {
        try {
            EventStoreProvider eventStore = session.getProvider(EventStoreProvider.class);
            if (eventStore != null && realm.isAdminEventsEnabled()) {
                AdminEvent adminEvent = new AdminEvent();
                adminEvent.setTime(Time.currentTimeMillis());
                adminEvent.setRealmId(realm.getId());
                adminEvent.setOperationType(operationType);
                adminEvent.setResourceType(ResourceType.COMPONENT);
                adminEvent.setResourcePath("components/" + component.getId());

                AuthDetails authDetails = new AuthDetails();
                authDetails.setRealmId(realm.getId());
                adminEvent.setAuthDetails(authDetails);

                Map<String, String> details = new java.util.HashMap<>();
                details.put("providerId", component.getProviderId());
                details.put("providerName", component.getName());
                details.put("message", message);

                try {
                    adminEvent.setRepresentation(org.keycloak.util.JsonSerialization.writeValueAsString(details));
                } catch (Exception e) {
                    logger.infov(e, "Failed to serialize event details");
                }

                eventStore.onEvent(adminEvent, true);
            }
        } catch (Exception e) {
            logger.warnv(e, "Failed to fire admin event for key rotation in realm '%s'", realm.getName());
        }
    }
}