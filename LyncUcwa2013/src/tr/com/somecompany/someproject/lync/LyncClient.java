package tr.com.somecompany.someproject.lync;

import java.awt.Image;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ObjectNode;

public final class LyncClient {
	private static final Logger logger = Logger.getLogger("LyncClient");

	private static Map<String, String> lyncRegistryMap;
	// clientId -- LyncAuthentication
	private static Map<String, LyncAuthentication> authenticationMap;

	private static final String LYNC_DISCOVERY_URL_KEY = "lyncDiscoveryUrl";
	private static final String LYNC_USERNAME_KEY = "lyncUsername";
	private static final String LYNC_ENCPASSWORD_KEY = "lyncEncPassword";

	private static final String RESPONSE1_LINKS_SELF_HREF = "_links-self-href";
	private static final String RESPONSE1_LINKS_USER_HREF = "_links-user-href";
	private static final String RESPONSE1_LINKS_XFRAME_HREF = "_links-xframe-href";
	private static final String RESPONSE_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
	private static final String RESPONSE_HEADER_VALUE_MSRTCOAUTH = "MsRtcOAuth";
	private static final String RESPONSE_HEADER_VALUE_BEARER = "Bearer";
	private static final String LYNC_EXT_POOL_URL_KEY = "extpoolUrl";


	private static final String PROTOCOL_HTTPS = "https";
	private static final String SSL_CONTEXT = "SSL";
	private static final int SSL_PORT = 443;
	private static byte[] key = { 0x74, 0x68, 0x69, 0x73, 0x49, 0x73, 0x41, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79 };

	// MsRtcOAuth
	// href="https://lyncextpool.somecompany.com.tr/WebTicket/oauthtoken",grant_type="urn:microsoft.rtc:windows,urn:microsoft.rtc:anonmeeting,password"
	private static final String PATTERN_MSRTCOAUTH = "MsRtcOAuth\\s*href=\"(.*)\",";
	private static final String PATTERN_KEY_MSRTCOAUTH = "MsRtcOAuth";

	// Bearer trusted_issuers="",
	// client_id="00000004-0000-0ff1-ce00-000000000000"
	private static final String PATTERN_BEARER = "(.*),\\s*client_id=\"(.*)\"";
	private static final String PATTERN_KEY_BEARER = "Bearer";

	private static HttpClient httpclient;
	private static final Map<String, Pattern> patternsMap;
	private static ObjectMapper mapper;

	static {
		lyncRegistryMap = new ConcurrentHashMap<String, String>();
		authenticationMap = new ConcurrentHashMap<String, LyncAuthentication>();

		patternsMap = new ConcurrentHashMap<String, Pattern>();
		patternsMap.put(PATTERN_KEY_MSRTCOAUTH, Pattern.compile(PATTERN_MSRTCOAUTH, Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
		patternsMap.put(PATTERN_KEY_BEARER, Pattern.compile(PATTERN_BEARER, Pattern.CASE_INSENSITIVE | Pattern.DOTALL));

		mapper = new ObjectMapper();
	}

	public void preapreClient(String username, String encPassword) {
		lyncRegistryMap.put(LYNC_DISCOVERY_URL_KEY, getDiscoveryUrl(username));
		lyncRegistryMap.put(LYNC_USERNAME_KEY, username);
		lyncRegistryMap.put(LYNC_ENCPASSWORD_KEY, encPassword);
		try {
			PoolingClientConnectionManager conMan = new PoolingClientConnectionManager();
			conMan.setMaxTotal(50);
			conMan.setDefaultMaxPerRoute(50);

			// Secure Protocol implementation.
			SSLContext ctx = SSLContext.getInstance(SSL_CONTEXT);
			// Implementation of a trust manager for X509 certificates
			X509TrustManager tm = new X509TrustManager() {

				public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
				}

				public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
				}

				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};
			ctx.init(null, new TrustManager[] { tm }, null);
			SSLSocketFactory ssf = new SSLSocketFactory(ctx);
			ssf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

			// register https protocol in httpclient's scheme registry
			SchemeRegistry sr = conMan.getSchemeRegistry();
			sr.register(new Scheme(PROTOCOL_HTTPS, SSL_PORT, ssf));

			httpclient = new DefaultHttpClient(conMan);
			//httpclient.getParams().setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.IGNORE_COOKIES);
		} catch (NoSuchAlgorithmException nsae) {
			logger.log(Level.WARNING, "", nsae);
		} catch (KeyManagementException kme) {
			logger.log(Level.WARNING, "", kme);
		}
	}

	/**
	 * get discovery URL from username.
	 * ex: john.doe@somecompany.com.tr -> https://lyncdiscover.somecompany.com.tr
	 * @param username username in "user@domain" format.
	 * @return lyncdiscover URL
	 */
	String getDiscoveryUrl(String username) throws IllegalArgumentException {
		int i = username.indexOf('@');
		if (i < 0) {
			throw new IllegalArgumentException("username does not contain '@':" + username);
		}
		return "https://lyncdiscover." + username.substring(i + 1);
	}

	/**
	 * @param response
	 */
	public void printResponseHeaders(HttpResponse response) {
		Header[] allHeaders = response.getAllHeaders();
		for (Header header : allHeaders) {
			logger.fine(header.getName() + ": " + header.getValue());
		}
	}

	public String getResponseHeaders(HttpResponse response) {
		StringBuilder sb = new StringBuilder();
		Header[] allHeaders = response.getAllHeaders();
		for (Header header : allHeaders) {
			sb.append(header.getName() + ": " + header.getValue() + "\n");
		}
		return sb.toString();
	}

	/**
	 * @param requestBase
	 */
	public void printRequestHeaders(HttpRequestBase requestBase) {
		Header[] allHeaders = requestBase.getAllHeaders();
		for (Header header : allHeaders) {
			logger.fine(header.getName() + ": " + header.getValue());
		}
	}

	public String getRequestHeaders(HttpRequestBase requestBase) {
		StringBuilder sb = new StringBuilder();
		Header[] allHeaders = requestBase.getAllHeaders();
		for (Header header : allHeaders) {
			sb.append(header.getName() + ": " + header.getValue() + "\n");
		}
		return sb.toString();
	}

	/**
	 * @param inputStream
	 * @return
	 * @throws IOException
	 */
	public String readHttpEntityBody(InputStream inputStream) throws IOException {
		String body = null;
		StringBuilder stringBuilder = new StringBuilder();
		BufferedReader bufferedReader = null;

		try {
			if (inputStream != null) {
				bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8")); // TODO: use charset from Content-Type
				char[] charBuffer = new char[128];
				int bytesRead = -1;
				while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
					stringBuilder.append(charBuffer, 0, bytesRead);
				}
			} else {
				stringBuilder.append("");
			}
		} catch (IOException ex) {
			throw ex;
		} finally {
			if (bufferedReader != null) {
				try {
					bufferedReader.close();
				} catch (IOException ex) {
					throw ex;
				}
			}
		}

		body = stringBuilder.toString();
		return body;
	}

	public static void main(String[] args) {
		System.out.println(LyncClient.encrypt(args[0]));
	}

	/**
	 * @param strToEncrypt
	 * @return
	 */
	public static String encrypt(String strToEncrypt) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			final String encryptedString = Base64.encodeBase64String(cipher.doFinal(strToEncrypt.getBytes()));
			return encryptedString;
		} catch (Exception e) {
			logger.warning("Error while encrypting" + e.getMessage());
		}
		return null;
	}

	/**
	 * @param strToDecrypt
	 * @return
	 */
	public static String decrypt(String strToDecrypt) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			final String decryptedString = new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt)));
			return decryptedString;
		} catch (Exception e) {
			logger.warning("Error while decrypting" + e.getMessage());
		}
		return null;
	}

	/**
	 * @param plainText
	 * @return
	 */
	public static String encode64(String plainText) {
		byte[] encoded = Base64.encodeBase64(plainText.getBytes());
		logger.fine("Original String: " + plainText);
		logger.fine("Base64 Encoded String : " + new String(encoded));
		return new String(encoded);
	}

	/**
	 * @param encoded
	 * @return
	 */
	public static String decode64(String encoded) {
		byte[] decoded = Base64.decodeBase64(encoded);
		logger.fine("Base 64 Decoded  String : " + new String(decoded));
		return new String(decoded);
	}

	private void setRequestData(LyncHttpOperationWrapper httpOpWrapper, HttpRequestBase request) {
		try {
			httpOpWrapper.setRequestHeaders(request.getAllHeaders());
			if (request instanceof HttpPost)
				httpOpWrapper.setRequestBody(readHttpEntityBody(((HttpPost) request).getEntity().getContent()));
		} catch (IllegalStateException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		}
	}

	private void setResponseData(LyncHttpOperationWrapper httpOpWrapper, HttpResponse response, int statusCode) {
		try {
			httpOpWrapper.setResponseHeaders(response.getAllHeaders());
			httpOpWrapper.setResponseBody(readHttpEntityBody(response.getEntity().getContent()));
			httpOpWrapper.setStatusCode(statusCode);
		} catch (IllegalStateException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		}
	}

	public LyncHttpOperationWrapper doFirstRequest() {
		HttpResponse response = null;
		HttpGet httpget = new HttpGet(lyncRegistryMap.get(LYNC_DISCOVERY_URL_KEY));
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();

		try {
			httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpget.setHeader(HttpHeaders.ACCEPT_ENCODING, "gzip,deflate,sdch");
			httpget.setHeader(HttpHeaders.ACCEPT_LANGUAGE, "en-US,en;q=0.8");
			httpget.setHeader(HttpHeaders.CONNECTION, "keep-alive");

			setRequestData(httpOpWrapper, httpget);

			logger.fine("REQUEST 1:" + httpget.getURI());
			logger.fine("-------------------------------");
			logger.fine("----Request Headers----");
			printRequestHeaders(httpget);

			try {
				response = httpclient.execute(httpget);
				logger.fine(response.getStatusLine().toString().toString());
				setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());
			} catch (HttpResponseException ex) {
			}
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} catch (Exception ex) {
			logger.log(Level.WARNING, "", ex);
		} finally {
			httpget.releaseConnection();
		}
		return httpOpWrapper;
	}

	/**
	 * @param userHref
	 * @param xframeHref
	 * @return
	 */
	public LyncHttpOperationWrapper doSecondRequest(String userHref, String xframeHref) {
		HttpResponse response = null;
		HttpGet httpget = new HttpGet(userHref);
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpget.setHeader(HttpHeaders.ACCEPT_ENCODING, "gzip,deflate,sdch");
			httpget.setHeader(HttpHeaders.ACCEPT_LANGUAGE, "en-US,en;q=0.8");
			httpget.setHeader(HttpHeaders.CONNECTION, "keep-alive");
			httpget.setHeader(HttpHeaders.REFERER, xframeHref);

			setRequestData(httpOpWrapper, httpget);
			logger.fine("\nREQUEST 2:" + httpget.getURI());
			logger.fine("-------------------------------");
			logger.fine("----Request Headers----");
			printRequestHeaders(httpget);

			response = httpclient.execute(httpget);
			setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());
			logger.fine(response.getStatusLine().toString().toString());
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} catch (Exception ex) {
			logger.log(Level.WARNING, "", ex);
		} finally {
			httpget.releaseConnection();
		}
		return httpOpWrapper;
	}

	/**
	 * @param OAuthUrl
	 *            https://lyncextpool.somecompany.com.tr/WebTicket/oauthtoken
	 * @return
	 */
	public LyncHttpOperationWrapper doThirdRequest(String OAuthUrl) {
		HttpResponse response = null;
		HttpPost httpPost = new HttpPost(OAuthUrl);
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			httpPost.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpPost.setHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded;charset=utf-8");
			httpPost.setHeader(HttpHeaders.ACCEPT_ENCODING, "gzip,deflate");
			httpPost.setHeader(HttpHeaders.ACCEPT_LANGUAGE, "en-US");
			httpPost.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache");
			httpPost.setHeader(HttpHeaders.CONNECTION, "keep-alive");
 
			List<NameValuePair> nvps = new ArrayList<NameValuePair>();
			nvps.add(new BasicNameValuePair("grant_type", "password"));
			nvps.add(new BasicNameValuePair("username", lyncRegistryMap.get(LYNC_USERNAME_KEY)));
			// enrcypt method of this class is used to avoid plain password in
			// code
			nvps.add(new BasicNameValuePair("password", decrypt(lyncRegistryMap.get(LYNC_ENCPASSWORD_KEY))));
			httpPost.setEntity(new UrlEncodedFormEntity(nvps));
 
			setRequestData(httpOpWrapper, httpPost);

			logger.fine("\nREQUEST 3:" + httpPost.getURI());
			// XXX: contains raw password
			//logger.fine("Request payload: " + httpOpWrapper.getRequestBody());
			logger.fine("-------------------------------");
			logger.fine("----Request Headers----");
			printRequestHeaders(httpPost);

			response = httpclient.execute(httpPost);
			setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());

			logger.fine(response.getStatusLine().toString().toString());
			printResponseHeaders(response);
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpPost.releaseConnection();
		}

		return httpOpWrapper;
	}

	/**
	 * @param userResourceUrl
	 *            https://lyncextpool.somecompany.com.tr/Autodiscover/
	 *            AutodiscoverService
	 *            .svc/root/oauth/user?originalDomain=somecompany.com.tr
	 * @param authHeaderValue
	 * @return
	 */
	public LyncHttpOperationWrapper doFourthRequest(String userResourceUrl, String authHeaderValue) {
		HttpResponse response = null;
		HttpGet httpget = new HttpGet(userResourceUrl);
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpget.setHeader(HttpHeaders.AUTHORIZATION, authHeaderValue);
			httpget.setHeader(HttpHeaders.ACCEPT_ENCODING, "gzip,deflate");
			httpget.setHeader(HttpHeaders.ACCEPT_LANGUAGE, "en-US");
			httpget.setHeader(HttpHeaders.CONNECTION, "keep-alive");

			setRequestData(httpOpWrapper, httpget);
			logger.fine("\nREQUEST 4:" + httpget.getURI());
			logger.fine("----Request Headers----");
			printRequestHeaders(httpget);

			response = httpclient.execute(httpget);
			setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());
			logger.fine(response.getStatusLine().toString().toString());
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpget.releaseConnection();
		}

		return httpOpWrapper;
	}

	/**
	 * @param applicationsUrl
	 *            https://lyncextpool.somecompany.com.tr/ucwa/oauth/v1/
	 *            applications
	 * @param authHeaderValue
	 * @param mapper
	 * @return
	 */
	public LyncHttpOperationWrapper doFifthRequest(String applicationsUrl, String authHeaderValue, String endPointId) {
		HttpResponse response = null;
		HttpPost httpPost = new HttpPost(applicationsUrl);
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			httpPost.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpPost.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
			httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeaderValue);

			httpPost.setHeader(HttpHeaders.ACCEPT_ENCODING, "gzip,deflate");
			httpPost.setHeader(HttpHeaders.ACCEPT_LANGUAGE, "en-US");
			httpPost.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache");
			httpPost.setHeader(HttpHeaders.CONNECTION, "keep-alive");

			Map<String, String> paramsMap = new HashMap<String, String>();
			paramsMap.put("UserAgent", "Java Client For UCWA");
			paramsMap.put("EndpointId", endPointId);
			paramsMap.put("Culture", "en-US");

			Writer strWriter = new StringWriter();
			mapper.writeValue(strWriter, paramsMap);
			httpPost.setEntity(new StringEntity(strWriter.toString(), ContentType.create("application/json")));

			setRequestData(httpOpWrapper, httpPost);
			logger.fine("\nREQUEST 5:" + httpPost.getURI());
			logger.fine("Request payload: " + httpOpWrapper.getRequestBody());
			logger.fine("-------------------------------");
			logger.fine("----Request Headers----");
			printRequestHeaders(httpPost);

			response = httpclient.execute(httpPost);
			setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());
			logger.fine(response.getStatusLine().toString().toString());
			printResponseHeaders(response);
			//logger.fine(httpOpWrapper.getResponseBody());
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpPost.releaseConnection();
		}

		return httpOpWrapper;
	}

	public String authenticate() {
		if (lyncRegistryMap.get(RESPONSE1_LINKS_SELF_HREF) == null || lyncRegistryMap.get(RESPONSE1_LINKS_USER_HREF) == null
				|| lyncRegistryMap.get(RESPONSE1_LINKS_XFRAME_HREF) == null) {
			// REQUEST 1
			LyncHttpOperationWrapper httpOpWrapper1 = doFirstRequest();
			if (httpOpWrapper1 != null) {
				String respBody = httpOpWrapper1.getResponseBody();
				logger.fine(respBody);
				JsonNode node;
				try {
					node = mapper.readTree(respBody);
					lyncRegistryMap.put(RESPONSE1_LINKS_SELF_HREF, node.get("_links").get("self").get("href").asText());
					lyncRegistryMap.put(RESPONSE1_LINKS_USER_HREF, node.get("_links").get("user").get("href").asText());
					lyncRegistryMap.put(RESPONSE1_LINKS_XFRAME_HREF, node.get("_links").get("xframe").get("href").asText());
				} catch (JsonProcessingException e) {
					logger.log(Level.WARNING, "", e);
				} catch (IllegalStateException e) {
					logger.log(Level.WARNING, "", e);
				} catch (IOException e) {
					logger.log(Level.WARNING, "", e);
				}
			}
		}

		// REQUEST 2
		LyncHttpOperationWrapper httpOpWrapper2 = doSecondRequest(lyncRegistryMap.get(RESPONSE1_LINKS_USER_HREF),
				lyncRegistryMap.get(RESPONSE1_LINKS_XFRAME_HREF));

		Header[] authHeaders = httpOpWrapper2.getResponseHeaderGroup(RESPONSE_HEADER_WWW_AUTHENTICATE);
		String OAuthHeaderValue = "";
		String clientIdHeaderValue = "";
		for (Header header : httpOpWrapper2.getResponseHeaders()) {
			logger.fine(header.getName() + ": " + header.getValue());
		}
		for (Header header : authHeaders) {
			if (header.getValue().contains(RESPONSE_HEADER_VALUE_MSRTCOAUTH)) {
				OAuthHeaderValue = header.getValue();
			}
			if (header.getValue().contains(RESPONSE_HEADER_VALUE_BEARER)) {
				clientIdHeaderValue = header.getValue();
			}
		}

		if (StringUtils.isEmpty(OAuthHeaderValue) || StringUtils.isEmpty(clientIdHeaderValue)) {
			logger.fine("OAuthHeaderValue / clientIdHeaderValue empty..");
			return null;
		}

		Matcher matcherMsRtcOauth = patternsMap.get(PATTERN_KEY_MSRTCOAUTH).matcher(OAuthHeaderValue);
		if (matcherMsRtcOauth.find()) {
			String OAuthUrl = matcherMsRtcOauth.group(1);
			logger.fine("Resolved OAuthUrl: " + OAuthUrl);

			Matcher matcherBearer = patternsMap.get(PATTERN_KEY_BEARER).matcher(clientIdHeaderValue);
			if (matcherBearer.find()) {
				String _clientId = matcherBearer.group(2);
				// REQUEST 3
				// preapreClient();
				LyncHttpOperationWrapper httpOpWrapper3 = doThirdRequest(OAuthUrl);

				try {
					JsonNode response3Json = mapper.readTree(httpOpWrapper3.getResponseBody());
					String accessToken = response3Json.get("access_token").getTextValue();
					// approximately 8 hours
					String expiresIn = response3Json.get("expires_in").toString();
					String tokenType = response3Json.get("token_type").getTextValue();

					String _authHeaderValue = tokenType + " " + accessToken;
					LyncAuthentication auth = new LyncAuthentication(_authHeaderValue, new Date(), Long.valueOf(expiresIn));
					authenticationMap.put(_clientId, auth);
					return _clientId;
				} catch (IllegalStateException e1) {
					logger.log(Level.WARNING, "", e1);
				} catch (IOException e1) {
					logger.log(Level.WARNING, "", e1);
				}
			} else {
				return null;
			}

		} else {
			return null;
		}
		return null;
	}

	public String createApplication() {
		String clientId = authenticate();
		// REQUEST 4
		LyncHttpOperationWrapper httpOpWrapper4 = doFourthRequest(lyncRegistryMap.get(RESPONSE1_LINKS_USER_HREF), authenticationMap.get(clientId)
				.getAccessToken());
		try {
			JsonNode response4Json = mapper.readTree(httpOpWrapper4.getResponseBody());
			String applicationsUrl = response4Json.get("_links").get("applications").get("href").getTextValue();
			URL appUrl = new URL(applicationsUrl);
			String domain = appUrl.getHost();
			String orgUserHref = lyncRegistryMap.get(RESPONSE1_LINKS_USER_HREF);
			String orgDomain = (new URL(orgUserHref)).getHost();
			if (!domain.equals(orgDomain)) { // split domain scenario
				lyncRegistryMap.put(RESPONSE1_LINKS_USER_HREF, orgUserHref.replace(orgDomain, domain));
				return createApplication();
			}
			lyncRegistryMap.put(LYNC_EXT_POOL_URL_KEY, appUrl.getProtocol() + "://" + domain + "/");

			// REQUEST 5
			LyncHttpOperationWrapper httpOpWrapper5 = doFifthRequest(applicationsUrl, authenticationMap.get(clientId).getAccessToken(), clientId);
			logger.fine("----Response Headers----");
			logger.fine(httpOpWrapper5.getResponseBody());

			JsonNode response5JsonNode = mapper.readTree(httpOpWrapper5.getResponseBody());
			authenticationMap.get(clientId).setResponse5JsonNode(response5JsonNode);

			return clientId;
		} catch (IllegalStateException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		}

		return null;
	}

	/**
	 * @param startMessagingUrl
	 * @param authHeaderValue
	 * @param mapper
	 * @return
	 */
	public LyncHttpOperationWrapper doStartMessagingRequest(String startMessagingUrl, String authHeaderValue, String subject, String message, String to) {
		HttpResponse response = null;
		HttpPost httpPost = new HttpPost(startMessagingUrl);
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			httpPost.setHeader(HttpHeaders.ACCEPT, "application/json");
			httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeaderValue);

			ObjectNode jNode = mapper.createObjectNode();
			jNode.put("to", to);
			jNode.put("subject", subject);
			jNode.put("operationId", "74cb7404e0a247d5a2d4eb0376a47dbf");
			// jNode.put("importance" : "Normal");
			// jNode.put("threadId", "292e0aaef36c426a97757f43dda19d06");

			ObjectNode messageNode = mapper.createObjectNode();
			messageNode.put("href", "data:text/plain;base64," + encode64(message));
			ObjectNode _linksNode = mapper.createObjectNode();
			_linksNode.put("message", messageNode);
			jNode.put("_links", _linksNode);
			httpPost.setEntity(new StringEntity(jNode.toString(), ContentType.create("application/json")));

			setRequestData(httpOpWrapper, httpPost);
			logger.fine("\nREQUEST StartMessaging:" + httpPost.getURI());
			logger.fine("----Request Headers----");
			printRequestHeaders(httpPost);

			response = httpclient.execute(httpPost);
			logger.fine(response.getStatusLine().toString().toString());
			setResponseData(httpOpWrapper, response, response.getStatusLine().getStatusCode());
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpPost.releaseConnection();
		}

		return httpOpWrapper;
	}

	public boolean peekAuthenticationMap() {
		if (authenticationMap.size() == 0)
			return false;
		return true;
	}

	public LyncAuthentication getAuthentication() {
		String clientId = (String) authenticationMap.keySet().toArray()[0];
		LyncAuthentication auth = authenticationMap.get(clientId);
		return auth;
	}

	public boolean removeTimedOutToken() {
		authenticationMap.clear();
		return authenticationMap.size() == 0;
	}

	public int sendMessage(String subject, String message, String to) {
		LyncHttpOperationWrapper httpOpWrapper = null;
		LyncAuthentication auth = getAuthentication();
		try {
			String startMessagingUrl = auth.getResponse5JsonNode().get("_embedded").get("communication").get("_links").get("startMessaging")
					.get("href").getTextValue();
			startMessagingUrl = lyncRegistryMap.get(LYNC_EXT_POOL_URL_KEY) + startMessagingUrl;
			logger.fine("startMessagingUrl:" + startMessagingUrl);
			httpOpWrapper = doStartMessagingRequest(startMessagingUrl, auth.getAccessToken(), subject, message, to);
		} catch (IllegalStateException e) {
			logger.log(Level.WARNING, "", e);
		}

		return httpOpWrapper == null ? LyncConstants.HTTP_RESPONSE_CODE_INERNAL_SERVER_ERROR : httpOpWrapper.getStatusCode();
	}

	public JsonNode doSearchRequest(String sip) {
		HttpResponse responseSearch = null;
		LyncAuthentication auth = getAuthentication();
		JsonNode responseSearchJsonNode = null;
		LyncHttpOperationWrapper httpOpWrapper = new LyncHttpOperationWrapper();
		try {
			String searchUrl = auth.getResponse5JsonNode().get("_embedded").get("people").get("_links").get("search").get("href").getTextValue();
			searchUrl = lyncRegistryMap.get(LYNC_EXT_POOL_URL_KEY) + searchUrl + "?Query=" + sip;
			logger.fine("searchUrl:" + searchUrl);

			HttpGet httpget = new HttpGet(searchUrl);
			try {
				httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
				httpget.setHeader(HttpHeaders.AUTHORIZATION, auth.getAccessToken());

				setRequestData(httpOpWrapper, httpget);
				responseSearch = httpclient.execute(httpget);
				logger.fine(responseSearch.getStatusLine().toString().toString());
				setResponseData(httpOpWrapper, responseSearch, responseSearch.getStatusLine().getStatusCode());

				logger.fine(httpOpWrapper.getResponseBody());
				responseSearchJsonNode = mapper.readTree(httpOpWrapper.getResponseBody());
			} catch (UnsupportedEncodingException e) {
				logger.log(Level.WARNING, "", e);
			} catch (ClientProtocolException e) {
				logger.log(Level.WARNING, "", e);
			} catch (IOException e) {
				logger.log(Level.WARNING, "", e);
			} finally {
				httpget.releaseConnection();
			}
		} catch (IllegalStateException e) {
			logger.log(Level.WARNING, "", e);
		}
		return responseSearchJsonNode;
	}

	public String doPresenceRequest(JsonNode responseSearchJsonNode) {
		LyncAuthentication auth = getAuthentication();
		HttpGet httpget = null;
		HttpResponse responsePresence = null;
		String presenceText = "unknown";
		try {
			Iterator<JsonNode> iter = responseSearchJsonNode.get("_embedded").get("contact").getElements();
			if (iter.hasNext()) {
				JsonNode firstNode = iter.next();
				String presenceUrl = firstNode.get("_links").get("contactPresence").get("href").getTextValue();

				presenceUrl = lyncRegistryMap.get(LYNC_EXT_POOL_URL_KEY) + presenceUrl;
				logger.fine("searchUrl:" + presenceUrl);

				httpget = new HttpGet(presenceUrl);

				httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
				httpget.setHeader(HttpHeaders.AUTHORIZATION, auth.getAccessToken());

				logger.fine("\nREQUEST Presence: " + httpget.getURI());
				logger.fine("----Request Headers----");
				printRequestHeaders(httpget);

				responsePresence = httpclient.execute(httpget);
				logger.fine(responsePresence.getStatusLine().toString().toString());

				printResponseHeaders(responsePresence);

				String responsePresenceBody = readHttpEntityBody(responsePresence.getEntity().getContent());
				logger.fine(responsePresenceBody);
				JsonNode responsePresenceJsonNode = mapper.readTree(responsePresenceBody);

				presenceText = responsePresenceJsonNode.get("availability").getTextValue();
				logger.fine("presenceText:" + presenceText);
			}

		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpget.releaseConnection();
		}
		return presenceText;
	}

	public String doContactNoteRequest(JsonNode responseSearchJsonNode) {
		LyncAuthentication auth = getAuthentication();
		HttpGet httpget = null;
		HttpResponse responseContactNote = null;
		String contactNote = "unknown";
		try {
			Iterator<JsonNode> iter = responseSearchJsonNode.get("_embedded").get("contact").getElements();
			if (iter.hasNext()) {
				JsonNode firstNode = iter.next();
				String contactNoteUrl = firstNode.get("_links").get("contactNote").get("href").getTextValue();

				contactNoteUrl = lyncRegistryMap.get(LYNC_EXT_POOL_URL_KEY) + contactNoteUrl;
				logger.fine("searchUrl:" + contactNoteUrl);

				httpget = new HttpGet(contactNoteUrl);

				httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
				httpget.setHeader(HttpHeaders.AUTHORIZATION, auth.getAccessToken());

				logger.fine("\nREQUEST Contact Note: " + httpget.getURI());
				logger.fine("----Request Headers----");
				printRequestHeaders(httpget);

				responseContactNote = httpclient.execute(httpget);
				logger.fine(responseContactNote.getStatusLine().toString());

				printResponseHeaders(responseContactNote);

				String responseContactNoteBody = readHttpEntityBody(responseContactNote.getEntity().getContent());
				logger.fine(responseContactNoteBody);
				JsonNode responseContactNoteJsonNode = mapper.readTree(responseContactNoteBody);

				contactNote = responseContactNoteJsonNode.get("message").getTextValue();
				logger.fine("contactNore:" + contactNote);
			}

		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpget.releaseConnection();
		}
		return contactNote;
	}

	public InputStream doContactPhotoRequest(JsonNode responseSearchJsonNode) {
		LyncAuthentication auth = getAuthentication();
		HttpGet httpget = null;
		HttpResponse responseContactPhoto = null;
		InputStream contactPohtoIs = null;
		try {
			Iterator<JsonNode> iter = responseSearchJsonNode.get("_embedded").get("contact").getElements();
			if (iter.hasNext()) {
				JsonNode firstNode = iter.next();
				String contactPhotoUrl = firstNode.get("_links").get("contactPhoto").get("href").getTextValue();

				contactPhotoUrl = lyncRegistryMap.get(LYNC_EXT_POOL_URL_KEY) + contactPhotoUrl;
				logger.fine("searchUrl:" + contactPhotoUrl);

				httpget = new HttpGet(contactPhotoUrl);

				httpget.setHeader(HttpHeaders.ACCEPT, "application/json");
				httpget.setHeader(HttpHeaders.AUTHORIZATION, auth.getAccessToken());

				logger.fine("\nREQUEST Contact Note: " + httpget.getURI());
				logger.fine("----Request Headers----");
				printRequestHeaders(httpget);

				responseContactPhoto = httpclient.execute(httpget);
				logger.fine(responseContactPhoto.getStatusLine().toString());

				printResponseHeaders(responseContactPhoto);
				String responseContactPhotoBody = readHttpEntityBody(responseContactPhoto.getEntity().getContent());

				contactPohtoIs = responseContactPhoto.getEntity().getContent();
				Image image = ImageIO.read(contactPohtoIs);
				logger.fine(image.getSource().toString());

				// logger.fine(responseContactNoteBody);
				// JsonNode responseContactPhotoJsonNode =
				// mapper.readTree(responseContactNoteBody);

				// contactPhoto =
				// responseContactPhotoJsonNode.get("message").getTextValue();
				// logger.fine("contactNore:" + contactNote);
			}

		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, "", e);
		} catch (ClientProtocolException e) {
			logger.log(Level.WARNING, "", e);
		} catch (IOException e) {
			logger.log(Level.WARNING, "", e);
		} finally {
			httpget.releaseConnection();
		}
		return contactPohtoIs;
	}

}
