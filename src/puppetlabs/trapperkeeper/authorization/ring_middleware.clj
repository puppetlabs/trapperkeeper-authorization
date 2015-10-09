(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [schema.core :as schema]
            [ring.middleware.params :as ring-params]
            [ring.util.codec :as ring-codec]
            [ring.util.request :as ring-request]
            [ring.util.response :as ring-response]
            [slingshot.slingshot :as sling]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.ssl-utils.core :as ssl-utils]
            [clojure.tools.logging :as log]
            [clojure.string :as str])
  (:import (clojure.lang IFn)
           (java.security.cert X509Certificate)
           (java.io StringReader)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schemas

(def AuthResultWithRequest
  (assoc rules/AuthorizationResult :req ring/Request))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Private

(def header-cert-name
  "Name of the HTTP header through which a client certificate can be passed
  for a request."
  "x-client-cert")

(def header-dn-name
  "Name of the HTTP header through which a client dn can be passed
  for a request."
  "x-client-dn")

(def header-client-verify-name
  "Name of the HTTP header through which a client verify can be passed
  for a request."
  "x-client-verify")

(defn warn-if-header-value-non-nil
  "Log a warning message if the supplied header-val is non-empty."
  [header-name header-val]
  (if header-val
    (log/warn "The HTTP header" header-name "was specified with" header-val
              "but the allow-header-cert-info was either not set, or was set"
              "to false.  This header will be ignored.")))

(defn throw-bad-request!
  "Throw a ::bad-request type slingshot error with the supplied message."
  [message]
  (sling/throw+ {:type ::bad-request :message message}))

(defn legacy-openssl-dn->cn
  "Attempt to parse the supplied 'dn' string as a legacy OpenSSL-style DN,
  where the attributes in the DN are delimited by solidus characters, and
  return back the value for a CN attribute found within it.  For example,
  if the supplied 'dn' were '/O=myorg/CN=myname', then the value returned
  would be 'myname'.  If a value for the CN attribute cannot be found, either
  because the original format of the 'dn' wasn't in the legacy OpenSSL-style
  or no CN attribute was found within the 'dn', this function would return
  nil."
  [dn]
  (when-not (nil? dn)
    (some #(if (= "CN" (first %1)) (second %1))
          (map #(str/split %1 #"=" 2) (str/split dn #"/")))))

(defn warn-for-empty-common-name
  "Log a warning message if the supplied common-name is empty (nil or empty
  string."
  ([common-name empty-message-format empty-message-arg1]
   (warn-for-empty-common-name common-name
                               empty-message-format
                               empty-message-arg1
                               ""))
  ([common-name empty-message-format empty-message-arg1 empty-message-arg2]
   (if (empty? common-name)
     (log/warnf (str empty-message-format
                     "  Treating client as 'unauthenticated'.")
                empty-message-arg1
                empty-message-arg2))
   common-name))

(defn request->name*
  "Pull the common name from the request, considering whether or not the
  name should be pulled from headers or an SSL certificate (per the
  allow-header-cert-info setting).  header-dn-val is the value of the
  DN in an HTTP header for the request, if available."
  [request header-dn-val allow-header-cert-info]
  (cond
    (not allow-header-cert-info)
      (do
        (warn-if-header-value-non-nil header-dn-name header-dn-val)
        (if-let [certificate (:ssl-client-cert request)]
          (warn-for-empty-common-name
           (ssl-utils/get-cn-from-x509-certificate certificate)
           "CN could not be found in certificate DN: %s."
           (-> certificate (.getSubjectDN) (.getName)))))
    (empty? header-dn-val)
      nil
    (ssl-utils/valid-x500-name? header-dn-val)
      (warn-for-empty-common-name (ssl-utils/x500-name->CN header-dn-val)
                                  (str "CN could not be found in RFC 2253 DN "
                                       "provided by HTTP header '%s': %s.")
                                  header-dn-name header-dn-val)
    :else
      (warn-for-empty-common-name (legacy-openssl-dn->cn header-dn-val)
                                  (str "CN could not be found in DN provided "
                                       "by HTTP header '%s': %s.")
                                  header-dn-name header-dn-val)))

(defn request->name
  "Pull the common name from the request, considering whether or not the
  name should be pulled from headers or an SSL certificate (per the
  allow-header-cert-info setting)."
  [request allow-header-cert-info]
  (request->name* request
                  (get-in request [:headers header-dn-name])
                  allow-header-cert-info))

(defn verified?
  "Determine if the user's identity has been 'verified'.  When
  'allow-header-cert-info' is set to 'true', the user's identity is assumed
  to be verified externally and, so, whatever the 'x-client-verify' header
  value is for the request is assumed to be the result of that verification.
  'SUCCESS' is the only value for a successful verification in that case;
  anything else is considered to be 'not verified'.  When
  'allow-header-cert-info' is set to 'false', the user's identity (or lack
  thereof) is assumed to have been verified by the server in which this
  code is running, in which case a value of 'true' is always returned"
  [request name allow-header-cert-info]
  (let [header-client-verify-val (get-in request
                                         [:headers header-client-verify-name])]
    (cond
      (not allow-header-cert-info)
        (do
          (warn-if-header-value-non-nil header-client-verify-name
                                        header-client-verify-val)
          true)
      (= header-client-verify-val "SUCCESS") true
      :else
        (do
          (if (not (empty? name))
            (log/errorf "Client with CN '%s' was not verified by '%s' header: '%s'"
                        name
                        header-client-verify-name
                        header-client-verify-val))
          false))))

(defn header-cert->pem
  "URL decode the header cert value into a PEM string."
  [header-cert]
  (try
    (ring-codec/url-decode header-cert)
    (catch Exception e
      (throw-bad-request!
       (str "Unable to URL decode the "
            header-cert-name
            " header: "
            (.getMessage e))))))

(defn pem->certs
  "Convert a pem string into certificate objects."
  [pem]
  (with-open [reader (StringReader. pem)]
    (try
      (ssl-utils/pem->certs reader)
      (catch Exception e
        (throw-bad-request!
         (str "Unable to parse "
              header-cert-name
              " into certificate: "
              (.getMessage e)))))))

(defn header->cert
  "Return an X509Certificate or nil from a string encoded for transmission
  in an HTTP header."
  [header-cert-val]
  (if header-cert-val
    (let [pem        (header-cert->pem header-cert-val)
          certs      (pem->certs pem)
          cert-count (count certs)]
      (condp = cert-count
        0 (throw-bad-request!
           (str "No certs found in PEM read from " header-cert-name))
        1 (first certs)
        (throw-bad-request!
         (str "Only 1 PEM should be supplied for "
              header-cert-name
              " but "
              cert-count
              " found"))))))

(schema/defn request->cert :- (schema/maybe X509Certificate)
  "Pull the client certificate from the request.  Response includes the
  certificate as a java.security.cert.X509Certificate object or, if none
  can be found, nil.  allow-header-cert-info determines whether to try to
  pull the certificate from an HTTP header (true) or from the certificate
  provided during SSL session negotiation (false)."
  [request :- ring/Request
   allow-header-cert-info :- schema/Bool]
  (let [header-cert-val (get-in request [:headers header-cert-name])]
    (if allow-header-cert-info
      (header->cert header-cert-val)
      (do
        (warn-if-header-value-non-nil header-cert-name header-cert-val)
        (:ssl-client-cert request)))))

(schema/defn add-authinfo :- ring/Request
  "Add authentication information to the ring request."
  [request :- ring/Request
   allow-header-cert-info :- schema/Bool]
  (let [name (request->name request allow-header-cert-info)]
    (->
      request
      (ring/set-authorized-name (str name))
      (ring/set-authorized-authentic? (and
                                       (verified? request
                                                  name
                                                  allow-header-cert-info)
                                       (not (empty? name))))
      (ring/set-authorized-certificate (request->cert request
                                                      allow-header-cert-info)))))

(defn assoc-query-params
  "Associate a `query-params` map onto the supplied request from any
  key/value pairs embedded in the request's URL query string."
  [request]
  (let [encoding (or (ring-request/character-encoding request) "UTF-8")]
    (if (:query-params request)
      request
      (ring-params/assoc-query-params request encoding))))

(defn bad-request?
  "Determine if the supplied slingshot message is for a 'bad request'"
  [x]
  (when (map? x) (= (:type x) ::bad-request)))

(defn output-error
  "Convert the supplied ring request, slingshot exception, and http status
  code into a Ring response with appropriate content."
  [{:keys [uri]} {:keys [message]} http-status]
  (log/errorf "Error %d on SERVER at %s: %s" http-status uri message)
  (-> (ring-response/response message)
      (ring-response/status http-status)
      (ring-response/content-type "text/plain")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(schema/defn authorization-check :- AuthResultWithRequest
  "A function that checks that the request is allowed by the provided rules.
  Returns a map with the request with auth info added, whether the request is
  authorized, and a message."
  [request :- ring/Request
   rules :- rules/Rules
   allow-header-cert-info :- schema/Bool]
  (let [req (add-authinfo request allow-header-cert-info)
        name (ring/authorized-name req)]
     (assoc (rules/allowed? rules req name) :req req)))

(schema/defn wrap-authorization-check :- IFn
  "A ring middleware that checks the request is allowed by the provided rules"
  [handler :- IFn
   rules :- rules/Rules
   allow-header-cert-info :- schema/Bool]
  (fn [request]
    (let [{:keys [authorized message req]}
          (authorization-check request rules allow-header-cert-info)]
      (if (true? authorized)
        (handler req)
        (-> (ring-response/response message)
            (ring-response/status 403))))))

(schema/defn wrap-query-params :- IFn
  "A ring middleware for destructuring query params from the request. This is
   similar to ring's wrap-params except that it only looks at query string and
   not at form params in the request body for a urlencodedform post.  tk-authz
   uses this so that it doesn't consume a request body before downstream
   middleware has a chance to access it."
  [handler :- IFn]
  (fn [request]
    (handler (assoc-query-params request))))

(schema/defn wrap-with-error-handling :- IFn
  "Middleware that wraps an authorization request with some error handling to
   return the appropriate http status codes, etc."
  [handler :- IFn]
  (fn [request]
    (sling/try+
     (handler request)
     (catch bad-request? e
       (output-error request e 400)))))
