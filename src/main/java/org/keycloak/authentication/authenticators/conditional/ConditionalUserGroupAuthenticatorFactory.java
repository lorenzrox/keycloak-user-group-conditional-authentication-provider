package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class ConditionalUserGroupAuthenticatorFactory implements AuthenticatorFactory {
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    public static final String GROUP_NAME = "group";
    public static final String NEGATE = "negate";

    public static final String PROVIDER_ID = "conditional-user-group";

    @Override
    public String getHelpText() {
        return "Flow is executed only if the user is member of the matching group";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty headerName = new ProviderConfigProperty();
        headerName.setType(ProviderConfigProperty.STRING_TYPE);
        headerName.setName(GROUP_NAME);
        headerName.setRequired(true);
        headerName.setLabel("Group name");
        headerName.setHelpText(
                "Group name that must match to execute this flow.");

        ProviderConfigProperty negateOutput = new ProviderConfigProperty();
        negateOutput.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        negateOutput.setName(NEGATE);
        negateOutput.setLabel("Negate output");
        negateOutput.setHelpText(
                "Apply a NOT to the check result. When this is true, then the condition will evaluate to true just if request headers do NOT match. When this is false, the condition will evaluate to true just if request headers do match");

        return Arrays.asList(headerName, negateOutput);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {
    }

    @Override
    public String getDisplayType() {
        return "Condition - User group";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return ConditionalUserGroupAuthenticator.SINGLETON;
    }
}