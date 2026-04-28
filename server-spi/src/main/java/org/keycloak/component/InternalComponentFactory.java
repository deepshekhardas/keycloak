package org.keycloak.component;

/**
 * Marker interface for {@link ComponentFactory} implementations that are managed internally
 * and should not be exposed through the generic component REST API.
 * <p>
 * Components backed by factories implementing this interface are managed through their own
 * dedicated APIs. Attempts to create, update, or delete them via the component endpoint
 * will be rejected.
 */
public interface InternalComponentFactory {
}
