(ns puppetlabs.trapperkeeper.authorization.ring-middleware
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.ssl-utils.core :as ssl-utils])
  (:import  (java.net InetAddress)
            (clojure.lang IFn)))


(schema/defn request->name :- schema/Str
             "Returns the embedded certificate CN if it exists, otherwise the reverse lookup of the ip address"
             [request :- ring/Request]
             (if-let [certificate (:ssl-client-cert request)]
               (ssl-utils/get-cn-from-x509-certificate certificate)
               (-> (InetAddress/getByName (:remote-addr request))
                   (.getCanonicalHostName))))

(schema/defn wrap-authorization-check :- IFn
             "A ring middleware that checks the request is allowed by the provided rules"
             [handler :- IFn
              rules :- rules/Rules]
             (fn [req]
               (let [{authorized :authorized msg :message} (rules/allowed? rules req (request->name req))]
                 (if authorized
                   (handler req)
                   {:status 401 :body msg}))))
