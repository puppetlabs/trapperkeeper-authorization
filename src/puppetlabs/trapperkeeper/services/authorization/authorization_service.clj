(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [puppetlabs.trapperkeeper.core :as trapperkeeper]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]))

(defprotocol AuthorizationService
  (wrap-handler [this handler]))

(trapperkeeper/defservice authorization-service
  AuthorizationService
  [[:ConfigService get-in-config]]
  (init
    [this context]
    (let [config (get-in-config [:authorization :rules])]
      (validate-auth-config! config)
      (assoc context :authorization {:rules (transform-config config)}))))
