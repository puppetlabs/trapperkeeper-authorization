(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [clojure.tools.logging :as log]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as
             ring-middleware]
            [puppetlabs.trapperkeeper.core :refer [defservice]]
            [puppetlabs.kitchensink.core :as ks]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [puppetlabs.trapperkeeper.services :refer [service-context]]))

(defprotocol AuthorizationService
  (wrap-with-authorization-check [this handler])
  (authorization-check [this request]))

(defservice authorization-service
  AuthorizationService
  [[:ConfigService get-in-config]]
  (init
   [this context]
   (let [config (get-in-config [:authorization])
         rules (-> config validate-auth-config! :rules transform-config)]
     (log/debug "Transformed auth.conf rules:\n" (ks/pprint-to-string rules))
     (-> context
         (assoc-in [:rules] rules)
         (assoc-in [:allow-header-cert-info] (get config
                                                  :allow-header-cert-info
                                                  false)))))

  (authorization-check [this request]
   (let [{:keys [rules allow-header-cert-info]} (service-context this)]
    (ring-middleware/authorization-check request rules allow-header-cert-info)))

  (wrap-with-authorization-check
   [this handler]
   (let [{:keys [allow-header-cert-info rules]} (service-context this)]
     (-> handler
         (ring-middleware/wrap-authorization-check rules allow-header-cert-info)
         ring-middleware/wrap-query-params
         ring-middleware/wrap-with-error-handling))))
