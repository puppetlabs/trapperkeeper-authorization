(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.ssl-utils.core :as ssl-utils])
  (:import  (clojure.lang IFn)))

(schema/defn request->name :- (schema/maybe schema/Str)
  "Return the identifying name of the request or nil"
  [request :- ring/Request]
  ; TODO TK-260 Return a name even if there is no SSL client cert
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
