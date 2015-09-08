(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [schema.core :as schema]
            [ring.middleware.params :as ring-params]
            [ring.util.request :as ring-request]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.ssl-utils.core :as ssl-utils])
  (:import  (clojure.lang IFn)))

(schema/defn request->name :- (schema/maybe schema/Str)
  "Return the identifying name of the request or nil"
  [request :- ring/Request]
  ; TODO SERVER-763 Support the name from the X headers
  (if-let [certificate (:ssl-client-cert request)]
    (ssl-utils/get-cn-from-x509-certificate certificate)))

(schema/defn add-authinfo :- ring/Request
  "Add authentication information to the ring request."
  [request :- ring/Request]
  (let [id (request->name request)]
    (->
      request
      (assoc-in ring/name-key (str id))
      ; TODO SERVER-763 Get authenticity from header if allow-header-cert-info
      (assoc-in ring/is-authentic-key (if id true false)))))

(schema/defn wrap-authorization-check :- IFn
  "A ring middleware that checks the request is allowed by the provided rules"
  [handler :- IFn
   rules :- rules/Rules]
  (fn [request]
    (let [req (add-authinfo request)
          name (get-in req ring/name-key "")
          {:keys [authorized message]} (rules/allowed? rules req name)]
      (if (true? authorized)
        (handler req)
        {:status 403 :body message}))))

(defn- assoc-query-params
  [request]
  (let [encoding (or (ring-request/character-encoding request) "UTF-8")]
    (if (:query-params request)
      request
      (ring-params/assoc-query-params request encoding))))

(schema/defn wrap-query-params :- IFn
  "A ring middleware for destructuring query params from the request. This is
   similar to ring's wrap-params except that it only looks at query string and
   not at form params in the request body for a urlencodedform post.  tk-authz
   uses this so that it doesn't consume a request body before downstream
   middleware has a chance to access it."
  [handler]
  (fn [request]
    (handler (assoc-query-params request))))
