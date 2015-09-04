(ns puppetlabs.trapperkeeper.authorization.ring
  (:require [schema.core :as schema])
  (:import (java.security.cert X509Certificate)))

(def is-authentic-key
  "The nested key where authenticity information is stored."
  [:authorization :authentic?])

(def name-key
  "The nested key where the identifying name of the request is stored."
  [:authorization :name])

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
