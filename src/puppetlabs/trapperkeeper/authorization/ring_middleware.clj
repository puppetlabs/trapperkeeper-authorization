(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.ssl-utils.core :as ssl-utils])
  (:import  (clojure.lang IFn)))

(def is-authentic-key
  "The nested key where authenticity information is stored."
  [:authorization :authentic?])

(def name-key
  "The nested key where the identifying name of the request is stored."
  [:authorization :name])

(schema/defn request->name :- (schema/maybe schema/Str)
  "Return the identifying name of the request or nil"
  ; TODO extract the name from the X headers
  [request :- ring/Request]
  (if-let [certificate (:ssl-client-cert request)]
    (ssl-utils/get-cn-from-x509-certificate certificate)))

(schema/defn add-authinfo :- ring/Request
  "Add authentication information to the ring request."
  [request :- ring/Request]
  (let [id (request->name request)]
    (->
      request
      (assoc-in name-key (str id))
      ; TODO SERVER-763 Get authenticity from header if allow-header-cert-info
      (assoc-in is-authentic-key (if id true false)))))

(schema/defn wrap-authorization-check :- IFn
  "A ring middleware that checks the request is allowed by the provided rules"
  [handler :- IFn
   rules :- rules/Rules]
  (fn [request]
    (let [req (add-authinfo request)
          name (get-in req name-key "")
          {:keys [authorized message]} (rules/allowed? rules req name)]
      (if (true? authorized)
        (handler req)
        {:status 403 :body message}))))
