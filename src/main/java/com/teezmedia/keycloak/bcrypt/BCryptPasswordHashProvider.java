package com.teezmedia.keycloak.bcrypt;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:pro.guillaume.leroy@gmail.com">Guillaume Leroy</a>
 * @author <a href="mailto:holly@teez-media.com">Holly Schöne</a>
 */
public class BCryptPasswordHashProvider implements PasswordHashProvider {
    private final int defaultIterations;
    private final String providerId;

    public BCryptPasswordHashProvider(String providerId, int defaultIterations) {
        this.providerId = providerId;
        this.defaultIterations = defaultIterations;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        int policyHashIterations = consolidateCost(policy.getHashIterations());

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        int cost = consolidateCost(iterations);
        String encodedPassword = encode(rawPassword, cost);

        // bcrypt salt is stored as part of the encoded password so no need to store salt separately
        return PasswordCredentialModel.createFromValues(providerId, new byte[0], cost, encodedPassword);
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        return BCrypt.with(BCrypt.Version.VERSION_2Y).hashToString(consolidateCost(iterations), rawPassword.toCharArray());
    }

    private int consolidateCost(int iterations) {
        return iterations < BCrypt.MIN_COST || iterations > BCrypt.MAX_COST ? defaultIterations : iterations;
    }

    @Override
    public void close() {

    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        final String hash = credential.getPasswordSecretData().getValue();
        BCrypt.Result verifier = BCrypt.verifyer().verify(rawPassword.toCharArray(), hash.toCharArray());
        return verifier.verified;
    }
}
