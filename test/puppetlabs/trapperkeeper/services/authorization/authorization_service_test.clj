(ns puppetlabs.trapperkeeper.services.authorization.authorization-service-test
  (:require
    [clojure.test :refer :all]
    [clojure.string :as str]
    [puppetlabs.trapperkeeper.app :refer [get-service]]
    [puppetlabs.trapperkeeper.authorization.testutils :refer :all]
    [puppetlabs.trapperkeeper.services :refer [defservice]]
    [puppetlabs.trapperkeeper.services.authorization.authorization-service :refer [authorization-service]]
    [puppetlabs.trapperkeeper.testutils.bootstrap :refer [with-app-with-config]]
    [puppetlabs.trapperkeeper.testutils.logging :refer [with-test-logging]]
    [ring.util.response :refer [response]]
    [schema.test :as schema-test]
    [puppetlabs.trapperkeeper.authorization.rules :as rules]))

(use-fixtures :once schema-test/validate-schemas)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utilities

(defprotocol EchoReverseService
  (echo-reverse [this msg]))

; A simple service using authorization via ring middleware
(defservice
  echo-reverse-service EchoReverseService
  [[:AuthorizationService wrap-with-authorization-check]]
  (echo-reverse
    [this msg]
    (let [handler (fn [req] (response (str msg (str/reverse (str (:body req))))))]
      (wrap-with-authorization-check handler))))

(def minimal-config
  "Minimal config required to bootstrap AuthorizationService with
  EchoReverseService as a dependant consumer.

  An empty list representing no rules with an expected behavior of
  default-deny originating in the authorization library itself."
  {:authorization {:rules []}})

(def basic-rules
  "Basic config exercising the use case of restricting a catalog to a node"
  [{:path "/puppet/v3/catalog/([^/]+)"
    :type "regex"
    :method :get
    :allow "$1"}])

(def basic-config
  "Minimal config with a basic rule layered on top."
  (assoc-in minimal-config [:authorization :rules] basic-rules))

(def default-rules
  "A representative example list of rules intended to model the defaults"
  [{:path "/puppet/v3/environments"
    :type "path"
    :allow "*"}])

(def catalog-request-nocert
  "A basic request for a catalog without a valid SSL cert"
  {:uri "/puppet/v3/catalog/localhost"
   :request-method :get
   :remote-addr "127.0.0.1"})

(def base-request
  "A basic request to feed into the tests"
  (request "/" :get (create-certificate "test.domain.org") "127.0.0.1" ))

(defn build-ring-handler
  "Build a ring handler around the echo reverse service"
  [rules]
  (fn [request]
    (with-test-logging
      (with-app-with-config
        app
        [echo-reverse-service authorization-service]
        (assoc-in minimal-config [:authorization :rules] rules)
        (let [svc (get-service app :EchoReverseService)
              echo-handler (echo-reverse svc "Prefix: ")]
          (echo-handler request))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest ^:integration wrap-handler-test
  (testing "With a default configuration list of rules"
    (let [app (build-ring-handler default-rules)]
      (let [req (assoc base-request :uri "/not/covered/by/default/rules")
            {:keys [status body]} (app req)]
        (is (= status 403))
        (is (= body "global deny all - no rules matched")))
      (let [req (-> base-request
                    (assoc :uri "/puppet/v3/environments")
                    (assoc :body "Hello World!"))
            {:keys [status body]} (app req)]
        (is (= status 200))
        (is (= body "Prefix: !dlroW olleH")))))
  (testing "With a minimal config of an empty list of rules"
    (let [app (build-ring-handler [])]
      (let [req (request "/path/to/foo" :get test-domain-cert "127.0.0.1")
            {:keys [status body]} (app req)]
        (is (= status 403))
        (is (= body "global deny all - no rules matched")))))
  (testing "With a basic config protecting the catalog"
    (let [app (build-ring-handler basic-rules)]
      (let [req (assoc catalog-request-nocert :body "Hello World!")
            {:keys [status body]} (app req)]
        (is (= status 403))
        (is (= body (str "Forbidden request: (127.0.0.1) "
                         "access to /puppet/v3/catalog/localhost "
                         "(method :get) (authentic: false)")))))))
