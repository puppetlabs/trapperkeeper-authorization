(ns examples.ring-app.ring-app
    (:require [clojure.tools.logging :as log]
              [puppetlabs.trapperkeeper.core :refer [defservice]]
              [puppetlabs.trapperkeeper.services :refer [service-context]]))

(defservice hello-service
            [[:AuthorizationService wrap-with-authorization-check]
             [:WebserverService add-ring-handler]]
            (init [this context]
                  (log/info "Hello service starting up")
                  (add-ring-handler
                   (wrap-with-authorization-check
                    (fn [_]
                        {:status  200
                         :headers {"Content-Type" "text/plain"}
                         :body    "Hello, World!"}))
                   "/hello")
                  context))
