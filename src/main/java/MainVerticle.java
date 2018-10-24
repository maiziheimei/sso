import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import netscape.javascript.JSObject;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.config.SAMLConfigurationInitializer;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.helpers.MessageFormatter;

import static sun.misc.Version.println;

public class MainVerticle {
    private static boolean isBootstrapped = false;

    public static void main(String[] args) throws InterruptedException {

        try { //initialization SAML service
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("SAML Service Initialization failed");
        }

        Vertx vertx = Vertx.vertx();
        HttpServer httpserver = vertx.createHttpServer();

        Router router = Router.router(vertx);

        // handle the get request from IDP, response with a saml request
        // e.g., gotoURL = http://ai-aid.edtec.berlin/content/smallDemonstrator"
        Route handler1 = router
                .get("/content/*")
                .handler(routingContext ->{

                    AuthnRequest at = AuthnRequestHandler.buildAuthnRequest();
                    String xmlString = OpenSAMLUtils.getSAMLObject(at);

                    // Redirect back to idp
                    routingContext.response()
                            .putHeader("location", Constants.IDP_SSO_SERVICE)
                            .putHeader("content-type","Application/xml; charset=utf-8").setStatusCode(302).end(xmlString);
                });


        // handle the post request from IDP with saml response, response with the specific process content
        //e.g., http://ai-aid.edtec.berlin/sso/sp/consumer";
        Route handler2 = router
                .post("/sso/sp/consumer")
                .consumes("Application/xml")
                .handler(routingContext -> {
                    System.out.println("receive IDP post request ... ");

                    //1. get assterion from request body
                    routingContext.request().bodyHandler(bodyHandler ->{
                       String xmlStr =  bodyHandler.toString();
                       System.out.println("request body string is: \n " + xmlStr);
                       try {
                           XMLObject xobj =  AssertionConsumerHandler.parseSAMLResponse(xmlStr);

                           // parse xml object to get user email address
                           int in =  xobj.getDOM().getElementsByTagName("saml2:AttributeValue").getLength();
                           String emailStr =xobj.getDOM().getElementsByTagName("saml2:AttributeValue").item(1).getFirstChild().getNodeValue();
                           System.out.println("... length: "+in + "... nameID: "+ emailStr );

                       }catch (Exception ex){
                           System.out.println("\n\n...hey Exception ..."+ ex.getMessage());
                       }
                    });

                    //2. after longin adwisar, then return required content process back to browser
                    HttpServerResponse response = routingContext.response();
                    response.setChunked(true);
                    response.write(" ... going to return the web page of http://ai-aid.edtec.berlin/content/smallDemonstrator \n");
                    response.end();
                });


        httpserver
                .requestHandler(router::accept)
                .listen(8091);

    }


        /**
         * Initializes the OpenSAML library modules, if not initialized yet.
         *
         * @throws Exception If unable to initialize
         */
        private static void initBootrap() throws Exception {
            try {
                if (!isBootstrapped) {
                    InitializationService.initialize();
                    SAMLConfigurationInitializer initializer = new SAMLConfigurationInitializer();
                    initializer.init();
                    isBootstrapped = true;
                }
            } catch (InitializationException e) {
                System.out.println("Unable to initialize OpenSAML library"+ e);
                throw new Exception("Unable to initialize OpenSAML library");
            }

        }




}
