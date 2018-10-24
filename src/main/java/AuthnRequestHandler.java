import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.AuthnRequest;

public class AuthnRequestHandler {

    // build authentication request from sp to idp
    public static AuthnRequest buildAuthnRequest() {
        System.out.println("... to build authnRequest \n ");
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        //set issue instant time for validation
        authnRequest.setIssueInstant(new DateTime());
        //set idp url
        authnRequest.setDestination(getIPDSSODestination());

        //set SAML assertion binding protocol, which is used Áritfact to get the real authentication info
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

        //set sp address: return the SAML assertin to this address
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());

        //set reqest id: a random id
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());

        //Issuer: SP's id or url
        authnRequest.setIssuer(buildIssuer());

        //NameID: idp uses for user identification; NameID policy is specification of NameID by SP
        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        // sp requirements on authentication, that is, the way that sp wished idp to authenticate the user
        // set requested Authentication Context
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());


        return authnRequest;
    }

    // *** below called by method buildAuthnRequest
    private static RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }
    private static String getIPDSSODestination() {
        return Constants.IDP_SSO_SERVICE;
    }
    private static String getAssertionConsumerEndpoint() {
        return Constants.SP_ASSERTION_CONSUMER_SERVICE;
    }
    private static Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }
    private static String getSPIssuerValue() {
        return Constants.SP_ENTITY_ID;
    }
    private static NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }
    // *** above called by the method buildAuthnRequest

}
