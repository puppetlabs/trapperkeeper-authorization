(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [puppetlabs.trapperkeeper.core :refer [defservice]]
            [puppetlabs.trapperkeeper.services :refer [service-context]]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :refer
             [wrap-authorization-check]]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]))

(defprotocol AuthorizationService
  (wrap-handler [this handler]))

(defservice authorization-service
  AuthorizationService
  [[:ConfigService get-in-config]]
  (init
    [this context]
    (let [config (get-in-config [:authorization :rules])]
      (validate-auth-config! config)
      (assoc-in context [:authorization :rules] (transform-config config))))

  (wrap-handler
    [this handler]
    (if-let [rules (get-in (service-context this) [:authorization :rules])]
      (wrap-authorization-check handler rules)
      (throw (IllegalStateException. (str "ERROR: No rules loaded."))))))
