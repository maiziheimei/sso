import com.sun.org.apache.xerces.internal.parsers.DOMParser;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.io.*;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.ArrayList;
import java.util.List;


public class AssertionConsumerHandler {
    private static final Logger logger = LoggerFactory.getLogger(AssertionConsumerHandler.class);

//    public static void start(HttpServerRequest request, HttpServerResponse response){
//        // suppose there is no sigh and encrypt
//        // body is just http reponse as xml message
//        // to
//
//    }

    public static XMLObject parseSAMLResponse(String xmlStringResponse) throws SamlException{

        // Response response;
        try{
            //InputStream source = new ByteArrayInputStream(xmlStringResponse.getBytes("UTF-8"));
            //try{
            //  response = (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), source);
            //   Assertion ass= response.getAssertions().get(0);
            //   System.out.println("... nameID: "+ ass.getSubject().getNameID().getValue());

            //}catch (XMLParserException e) {
            //   e.printStackTrace();
            //}

            DOMParser parser = createDOMParser();
            parser.parse(new InputSource(new StringReader(xmlStringResponse)));

            XMLObject xobj =  XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                        .getUnmarshaller(parser.getDocument().getDocumentElement())
                    .unmarshall(parser.getDocument().getDocumentElement());



        return xobj;

    }catch (IOException | SAXException | UnmarshallingException ex) {
            throw new SamlException("Cannot decode xml encoded response", ex);
        }
    }




    private static SamlResponse decodeAndValidateSamlResponse(String xmlStringResponse) throws SamlException {
        Response response;
        try {
            DOMParser parser = createDOMParser();
            parser.parse(new InputSource(new StringReader(xmlStringResponse)));
            response =
                    (Response)
                            XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                                    .getUnmarshaller(parser.getDocument().getDocumentElement())
                                    .unmarshall(parser.getDocument().getDocumentElement());
        } catch (IOException | SAXException | UnmarshallingException ex) {
            throw new SamlException("Cannot decode xml encoded response", ex);
        }


        Assertion assertion = response.getAssertions().get(0);

        System.out.println( "... get assertion nameID value:" + assertion.getSubject().getNameID().getValue());

        return new SamlResponse(assertion);
    }


    private static DOMParser createDOMParser() throws SamlException {
        DOMParser parser =
                new DOMParser() {
                    {
                        try {
                            setFeature(INCLUDE_COMMENTS_FEATURE, false);
                        } catch (Throwable ex) {
                            throw new SamlException(
                                    "Cannot disable comments parsing to mitigate https://www.kb.cert.org/vuls/id/475445",
                                    ex);
                        }
                    }
                };

        return parser;
    }

    // get attribut from assertion
    private void getAssertionAttributes(Assertion assertion) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            logger.info("Attribute name: " + attribute.getName());
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
            }
        }
    }

}
