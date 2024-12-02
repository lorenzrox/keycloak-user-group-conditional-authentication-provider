package org.keycloak.authentication.authenticators.conditional;

import java.util.Map;
import java.util.Objects;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class ConditionalUserGroupAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalUserGroupAuthenticator SINGLETON = new ConditionalUserGroupAuthenticator();

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        boolean negateOutput = Boolean.parseBoolean(config.get(ConditionalUserAttributeValueFactory.CONF_NOT));
        String groupName = config.get(ConditionalUserGroupAuthenticatorFactory.GROUP_NAME);

        UserModel user = context.getUser();
        if (user == null) {
            throw new AuthenticationFlowException(
                    "Cannot find user for obtaining particular user groups. Authenticator: "
                            + ConditionalUserAttributeValueFactory.PROVIDER_ID,
                    AuthenticationFlowError.UNKNOWN_USER);
        }

        return user.getGroupsStream().anyMatch(group -> Objects.equals(group.getName(), groupName)) != negateOutput;
    }

    @Override
    public void close() {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }
}
