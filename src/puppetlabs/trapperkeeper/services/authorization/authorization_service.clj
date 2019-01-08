(ns puppetlabs.trapperkeeper.services.authorization.authorization-service
  (:require [clojure.tools.logging :as log]
            [puppetlabs.i18n.core :refer [trs]]
            [puppetlabs.kitchensink.core :as ks]
            [puppetlabs.rbac-client.protocols.rbac
             :as
             rbac
             :refer
             [RbacConsumerService]]
            [puppetlabs.ring-middleware.core :as mw]
            [puppetlabs.trapperkeeper.authorization.ring-middleware
             :as
             ring-middleware]
            [puppetlabs.trapperkeeper.core :refer [defservice]]
            [puppetlabs.trapperkeeper.services
             :refer
             [maybe-get-service service-context]]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core
             :refer
             :all]))

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
         rules (-> config validate-auth-config! :rules transform-config)
         is-permitted? (if-let [rbac-service (maybe-get-service this :RbacConsumerService)]
                         (partial rbac/is-permitted? rbac-service))
         token->subject (if-let [rbac-service (maybe-get-service this :RbacConsumerService)]
                          (partial rbac/valid-token->subject rbac-service))]
     (log/debug (trs "Transformed auth.conf rules:\n{0}") (ks/pprint-to-string rules))
     (-> context
         (assoc :is-permitted? is-permitted?)
         (assoc :token->subject token->subject)
         (assoc-in [:rules] rules)
         (assoc-in [:allow-header-cert-info] (get config
                                                  :allow-header-cert-info
                                                  false)))))

  (authorization-check [this request]
   (authorization-check this request {:oid-map {}}))

  (authorization-check [this request {:keys [oid-map]}]
   (let [{:keys [rules allow-header-cert-info is-permitted? token->subject]} (service-context this)]
    (ring-middleware/authorization-check request rules oid-map allow-header-cert-info is-permitted? token->subject)))

  (wrap-with-authorization-check
   [this handler]
   (wrap-with-authorization-check this handler {:oid-map {}}))

  (wrap-with-authorization-check
   [this handler {:keys [oid-map]}]
   (let [{:keys [allow-header-cert-info rules is-permitted? token->subject]} (service-context this)]
     (-> handler
         (ring-middleware/wrap-authorization-check rules oid-map allow-header-cert-info is-permitted? token->subject)
         (mw/wrap-bad-request :plain)))))
