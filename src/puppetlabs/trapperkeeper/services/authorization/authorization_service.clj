(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [clojure.tools.logging :as log]
            [puppetlabs.ring-middleware.core :as mw]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as
             ring-middleware]
            [puppetlabs.trapperkeeper.core :refer [defservice]]
            [puppetlabs.kitchensink.core :as ks]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [puppetlabs.trapperkeeper.services :refer [service-context]]
            [puppetlabs.rbac-client.protocols.rbac :refer [RbacConsumerService]]
            [puppetlabs.i18n.core :refer [trs]]))

(defprotocol AuthorizationService
  (wrap-with-authorization-check [this handler] [this handler options])
  (authorization-check [this request] [this handler options]))

(defservice authorization-service
  AuthorizationService
  {:required [[:ConfigService get-in-config]]
   :optional [RbacConsumerService]}
  (init
   [this context]
   (let [config (get-in-config [:authorization])
         rules (-> config validate-auth-config! :rules transform-config)]
     (log/debug (trs "Transformed auth.conf rules:\n{0}") (ks/pprint-to-string rules))
     (-> context
         (assoc-in [:rules] rules)
         (assoc-in [:allow-header-cert-info] (get config
                                                  :allow-header-cert-info
                                                  false)))))

  (authorization-check [this request]
   (authorization-check this request {:oid-map {}}))

  (authorization-check [this request {:keys [oid-map]}]
   (let [{:keys [rules allow-header-cert-info]} (service-context this)]
    (ring-middleware/authorization-check request rules oid-map allow-header-cert-info)))

  (wrap-with-authorization-check
   [this handler]
   (wrap-with-authorization-check this handler {:oid-map {}}))

  (wrap-with-authorization-check
   [this handler {:keys [oid-map]}]
   (let [{:keys [allow-header-cert-info rules]} (service-context this)]
     (-> handler
         (ring-middleware/wrap-authorization-check rules oid-map allow-header-cert-info)
         (mw/wrap-bad-request :plain)))))
