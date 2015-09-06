(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [puppetlabs.trapperkeeper.authorization.ring-middleware :refer
             [wrap-authorization-check wrap-query-params]]
            [puppetlabs.trapperkeeper.core :refer [defservice]]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [puppetlabs.trapperkeeper.services :refer [service-context]]))

(defprotocol AuthorizationService
  (wrap-with-authorization-check [this handler]))

(defservice authorization-service
  AuthorizationService
  [[:ConfigService get-in-config]]
  (init
    [this context]
    (let [config (get-in-config [:authorization :rules])]
      (validate-auth-config! config)
      (assoc-in context [:rules] (transform-config config))))

  (wrap-with-authorization-check
    [this handler]
    (let [rules (get-in (service-context this) [:rules])]
      (-> handler
          (wrap-authorization-check rules)
          wrap-query-params))))
