(ns puppetlabs.trapperkeeper.authorization.ring
  (:require [schema.core :as schema]
            [clojure.string :as str])
  (:import (java.security.cert X509Certificate)))

;; schema

(def RequestMethod (schema/enum :get :post :put :delete :head :options))

(def Request
  "A ring request with an embedded optional SSL client certificate."
  {:uri schema/Str
   :request-method RequestMethod
   :remote-addr schema/Str
   schema/Keyword schema/Any})

;; utilities
