(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [puppetlabs.i18n.core :refer [trs tru]]
            [puppetlabs.ring-middleware.utils :as ringutils]
            [puppetlabs.ssl-utils.core :as ssl-utils]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [ring.middleware.params :as ring-params]
            [ring.util.codec :as ring-codec]
            [ring.util.request :as ring-request]
            [ring.util.response :as ring-response]
            [schema.core :as schema]
            [slingshot.slingshot :as sling])
  (:import (clojure.lang IFn)
           (java.io StringReader)
           (java.security.cert X509Certificate)))

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
  (when header-val
    (log/warn (trs "The HTTP header {0} was specified with {1} but the allow-header-cert-info was either not set, or was set to false. This header will be ignored." header-name header-val))))

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
    (some #(when (= "CN" (first %1)) (second %1))
          (map #(str/split %1 #"=" 2) (str/split dn #"/")))))

(defn warn-for-empty-common-name
  "Log a warning message if the supplied common-name is empty (nil or empty
  string."
  [common-name empty-message]
  (if (empty? common-name)
    (log/warn (trs "{0} Treating client as ''unauthenticated''." empty-message))
    (log/trace (trs "Common name is {0}" common-name)))
  common-name)

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
          (let [error-message (trs "CN could not be found in certificate DN")
                cert-dn (ssl-utils/get-subject-from-x509-certificate certificate)]
            (warn-for-empty-common-name
             (ssl-utils/get-cn-from-x509-certificate certificate)
             (format "%s: %s." error-message cert-dn)))
          (log/debug (trs "No certificate found in request for name resolution."))))
    (empty? header-dn-val)
      nil
    (ssl-utils/valid-x500-name? header-dn-val)
      (let [error-message (trs "CN could not be found in RFC 2253 DN provided by HTTP header")]
        (warn-for-empty-common-name (ssl-utils/x500-name->CN header-dn-val)
                                    (format "%s '%s': %s."
                                            error-message
                                            header-dn-name
                                            header-dn-val)))
    :else
      (let [error-message (trs "CN could not be found in DN provided by HTTP header")]
        (warn-for-empty-common-name (legacy-openssl-dn->cn header-dn-val)
                                    (format "%s '%s': %s."
                                            error-message
                                            header-dn-name
                                            header-dn-val)))))

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
    (log/trace (trs "header-client-verify-val: " header-client-verify-val))
    (cond
      (not allow-header-cert-info)
        (do
          (warn-if-header-value-non-nil header-client-verify-name
                                        header-client-verify-val)
          true)
      (= header-client-verify-val "SUCCESS") true
      :else
        (do
          (when (seq name)
            ; Translator note: {1} is the header name, {2} is the header value
            (log/error (trs "Client with CN ''{0}'' was not verified by ''{1}'' header: ''{2}''"
                             name
                             header-client-verify-name
                             header-client-verify-val)))
          false))))

(defn header-cert->pem
  "URL decode the header cert value into a PEM string."
  [header-cert]
  (try
    (ring-codec/url-decode header-cert)
    (catch Exception e
      (ringutils/throw-bad-request!
       (tru "Unable to URL decode the {0} header: {1}" header-cert-name (.getMessage e))))))

(defn pem->certs
  "Convert a pem string into certificate objects."
  [pem]
  (with-open [reader (StringReader. pem)]
    (try
      (ssl-utils/pem->certs reader)
      (catch Exception e
        (ringutils/throw-bad-request!
         (tru "Unable to parse {0} into certificate: {1}" header-cert-name (.getMessage e)))))))

(defn header->cert
  "Return an X509Certificate or nil from a string encoded for transmission
  in an HTTP header."
  [header-cert-val]
  (when header-cert-val
    (let [pem        (header-cert->pem header-cert-val)
          certs      (pem->certs pem)
          cert-count (count certs)]
      (condp = cert-count
        0 (ringutils/throw-bad-request!
           (tru "No certs found in PEM read from {0}" header-cert-name))
        1 (first certs)
        (ringutils/throw-bad-request!
         (tru "Only 1 PEM should be supplied for {0} but {1} found" header-cert-name cert-count))))))

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
      (:ssl-client-cert request))))

(schema/defn request->extensions :- acl/Extensions
  "Given a request, return a map of shortname -> value for all of the extensions
  in the request's certificate. Uses the passed oid map to translate from OIDs
  to short names."
  [request :- ring/Request
   allow-header-cert-info :- schema/Bool
   oid-map :- acl/OIDMap]
  (if-let [cert (request->cert request allow-header-cert-info)]
    (let [oid-map (merge acl/default-oid-map oid-map)
          extensions (ssl-utils/get-extensions cert)
          translate-oids (fn [out extension]
                           (let [oid-key (get oid-map (:oid extension)
                                              (keyword (:oid extension)))
                                 value (condp = oid-key
                                         :subject-alt-name (:value extension)
                                         (str (:value extension)))]
                             (assoc out oid-key value)))]
      (reduce translate-oids {} extensions))
    {}))

(schema/defn add-authinfo :- ring/Request
  "Add authentication information to the ring request."
  [request :- ring/Request
   allow-header-cert-info :- schema/Bool
   oid-map :- acl/OIDMap]
  (let [name (request->name request allow-header-cert-info)
        extensions (request->extensions request
                                        allow-header-cert-info
                                        oid-map)]
    (log/trace (trs "Authorized name: {0}" name))
    (log/trace (trs "Allow-header-cert-info: {0}" allow-header-cert-info))
    (->
      request
      (ring/set-authorized-name name)
      (ring/set-authorized-extensions extensions)
      (ring/set-authorized-authenticated (and
                                           (verified? request
                                                      name
                                                      allow-header-cert-info)
                                           (some? (seq name))))
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

(defn- rbac-error?
  "Return true if an exception comes from puppetlabs-rbac* libraries (rbac or rbac-client)"
  [err]
  (some-> err
          :kind
          namespace
          (str/starts-with? "puppetlabs.rbac")))

(schema/defn add-rbac-subject
  [request :- ring/Request
   token->subject :- (schema/maybe IFn)]
  (if token->subject
    (if-let [token (get-in request [:headers "x-authentication"])]
      (sling/try+
        (assoc request :rbac-subject (token->subject token))
        (catch rbac-error? {:keys [msg]}
          (log/error "Failure validating RBAC token:" msg)
          (assoc request :rbac-error msg)))
      request)
    request))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(schema/defn authorization-check :- rules/AuthorizationResult
  "Checks that the request is allowed by the provided rules and returns an
   authorization result map containing the request with authorization info
   added, whether the request is authorized, and a message."
  [request :- ring/Request
   rules :- [rules/Rule]
   oid-map :- acl/OIDMap
   allow-header-cert-info :- schema/Bool
   rbac-is-permitted? :- (schema/maybe IFn)
   token->subject :- (schema/maybe IFn)]
  (-> request
      assoc-query-params
      (add-authinfo allow-header-cert-info oid-map)
      (add-rbac-subject token->subject)
      (rules/allowed? rules oid-map rbac-is-permitted?)))

(schema/defn wrap-authorization-check :- IFn
  "Middleware that checks if the request is allowed by the provided rules,
   and if not returns a 403 response with a user-friendly message."
  [handler :- IFn
   rules :- [rules/Rule]
   oid-map :- acl/OIDMap
   allow-header-cert-info :- schema/Bool
   rbac-is-permitted? :- (schema/maybe IFn)
   token->subject :- (schema/maybe IFn)]
  (fn [req]
    (let [{:keys [authorized message request]}
          (authorization-check req rules oid-map allow-header-cert-info rbac-is-permitted? token->subject)]
      (if (true? authorized)
        (handler request)
        (-> (ring-response/response message)
            (ring-response/status 403))))))

