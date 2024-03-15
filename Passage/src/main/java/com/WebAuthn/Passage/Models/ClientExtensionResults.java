package com.WebAuthn.Passage.Models;

public class ClientExtensionResults {
    private CredProps credProps;

    public ClientExtensionResults() {
    }

    public CredProps getCredProps() {
        return credProps;
    }

    public void setCredProps(CredProps credProps) {
        this.credProps = credProps;
    }

    public static class CredProps {
        private Object rk;

        public CredProps() {
        }

        public Object getRk() {
            return rk;
        }

        public void setRk(Object rk) {
            this.rk = rk;
        }

    }
}
