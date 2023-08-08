(ns examples.ring-app.repl
  (:require
    [clojure.pprint :refer [pprint]]
    [clojure.tools.namespace.repl :refer [refresh]]
    [examples.ring-app.ring-app :refer [hello-service]]
    [puppetlabs.trapperkeeper.app :as tka]
    [puppetlabs.trapperkeeper.core :as tk]
    [puppetlabs.trapperkeeper.services.authorization.authorization-service
     :refer [authorization-service]]
    [puppetlabs.trapperkeeper.services.webserver.jetty9-service
     :refer [jetty9-service]]))

;; This namespace shows an example of the "reloaded" clojure workflow
;; ( http://thinkrelevance.com/blog/2013/06/04/clojure-workflow-reloaded )
;;
;; It's based on the pattern from Stuart Sierra's `Component` library:
;; ( https://github.com/stuartsierra/component#reloading )
;;
;; You can load this namespace up into a REPL and then run `(go)` to boot
;; and run the sample application.  Then, you can run `(reset)` at any time
;; to stop the running app, reload all of the necessary namespaces, and start
;; a new instance of the app.  This means that you can do iterative development
;; without having to restart the whole JVM.
;;
;; You can also view the context of the application (and all of the
;; trapperkeeper services) via `(context)` (or pretty-printed with
;; `print-context`).

(def system nil)

(defn init []
  (alter-var-root #'system
                  (fn [_] (tk/build-app
                           [jetty9-service
                            authorization-service
                            hello-service]
                           {:global
                            {:logging-config "./examples/ring_app/logback.xml"}
                            :webserver {:client-auth "want"
                                        :port 8080
                                        :ssl-port 8081
                                        :ssl-cert
                                        "./examples/ring_app/ssl/certs/localhost.pem"
                                        :ssl-ca-cert
                                        "./examples/ring_app/ssl/certs/ca.pem"
                                        :ssl-key
                                        "./examples/ring_app/ssl/private_keys/localhost.pem"}
                            :authorization {:version 1
                                            :rules [{:match-request
                                                     {:path
                                                      "/hello/all-allowed"
                                                      :type "path"}
                                                     :allow-unauthenticated true
                                                     :name
                                                     "all users allowed"
                                                     :sort-order 500}
                                                    {:match-request
                                                     {:path
                                                      "/hello/user-allowed/([^/]+)$"
                                                      :type "regex"}
                                                     :allow "$1"
                                                     :name
                                                     "users allowed by backreference"
                                                     :sort-order 500}]}})))
  (alter-var-root #'system tka/init)
  (tka/check-for-errors! system))

(defn start []
  (alter-var-root #'system
                  (fn [s] (if s (tka/start s))))
  (tka/check-for-errors! system))

(defn stop []
  (alter-var-root #'system
                  (fn [s] (if s (tka/stop s)))))

(defn go []
  (init)
  (start))

(defn context []
  @(tka/app-context system))

(defn print-context []
  (pprint (context)))

(defn reset []
  (stop)
  (refresh :after 'examples.ring-app.repl/go))
