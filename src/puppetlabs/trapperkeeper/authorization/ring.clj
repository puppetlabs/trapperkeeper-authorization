(ns puppetlabs.trapperkeeper.authorization.ring
  (:require [schema.core :as schema])
  (:import (java.security.cert X509Certificate)))

;; schema

(def RequestMethod (schema/enum :get :post :put :delete :head :options))

(def Request
  "A ring request with an embedded optional SSL client certificate."
  {:uri schema/Str
   :request-method RequestMethod
   :remote-addr schema/Str
   (schema/optional-key :ssl-client-cert) (schema/maybe X509Certificate)
   schema/Keyword schema/Any})

;; Functions

(schema/defn authorized-authentic? :- schema/Bool
  "Get whether the authorized client is considered authentic or not."
  [request :- Request]
  (get-in request [:authorization :authentic?]))

(schema/defn set-authorized-authentic? :- Request
  "Set whether the authorized client is considered authentic or not."
  [request :- Request
   authentic? :- schema/Bool]
  (assoc-in request [:authorization :authentic?] authentic?))

(schema/defn authorized-certificate :- (schema/maybe X509Certificate)
  "Get the certificate of the authorized client."
  [request :- Request]
  (get-in request [:authorization :certificate]))

(schema/defn set-authorized-certificate :- Request
  "Get the certificate of the authorized client."
  [request :- Request
   certificate :- (schema/maybe X509Certificate)]
  (assoc-in request [:authorization :certificate] certificate))

(schema/defn authorized-name :- schema/Str
  "Get the authorized client name from the request."
  [request :- Request]
  (get-in request [:authorization :name] ""))

(schema/defn set-authorized-name :- Request
  "Set the authorized client name onto the request."
  [request :- Request
   name :- (schema/maybe schema/Str)]
  (assoc-in request [:authorization :name] (str name)))
