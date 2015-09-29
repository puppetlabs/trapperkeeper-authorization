(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [puppetlabs.trapperkeeper.authorization.ring-middleware :as
             ring-middleware]
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
    (let [config (get-in-config [:authorization])]
      (validate-auth-config! config)
      (-> context
          (assoc-in [:rules] (transform-config (:rules config)))
          (assoc-in [:allow-header-cert-info] (get config
                                                   :allow-header-cert-info
                                                   false)))))

  (wrap-with-authorization-check
    [this handler]
    (let [{:keys [allow-header-cert-info rules]} (service-context this)]
      (-> handler
          (ring-middleware/wrap-authorization-check rules allow-header-cert-info)
          ring-middleware/wrap-query-params
          ring-middleware/wrap-with-error-handling))))
