(ns puppetlabs.trapperkeeper.services.authorization.authorization-service-test
  (:require
    [clojure.test :refer :all]
    [clojure.string :as str]
    [puppetlabs.trapperkeeper.app :refer [get-service]]
    [puppetlabs.trapperkeeper.services :refer [defservice]]
    [puppetlabs.trapperkeeper.services.authorization.authorization-service :refer [authorization-service]]
    [puppetlabs.trapperkeeper.testutils.bootstrap :refer [with-app-with-config]]
    [puppetlabs.trapperkeeper.testutils.logging :refer [with-test-logging]]
    [ring.util.response :refer [response]]
    [schema.test :as schema-test]))

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
    (let [handler (fn [req] (response (str msg (str/reverse (:body req)))))]
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

(def catalog-request-nocert
  "A basic request for a catalog without a valid SSL cert"
  {:uri "/puppet/v3/catalog/localhost"
   :request-method :get
   :remote-addr "127.0.0.1"})

(def base-request
  "A basic request to feed into the tests"
  {:uri "/foo/bar"
   :request-method :get
   :remote-addr "127.0.0.1"})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest ^:integration wrap-handler-test
  (with-test-logging
    (testing "With a minimal config of an empty list of rules"
      (with-app-with-config
        app
        [echo-reverse-service authorization-service]
        minimal-config
        (let [svc (get-service app :EchoReverseService)
              echo-handler (echo-reverse svc "Prefix: ")
              req (assoc base-request :body "Hello World!")
              {:keys [body status]} (echo-handler req)]
          (is (= 401 status))
          (is (= "global deny all - no rules matched" body)))))
    (testing "With a basic config protecting the catalog"
      (with-app-with-config
        app
        [echo-reverse-service authorization-service]
        basic-config
        (let [svc (get-service app :EchoReverseService)
              echo-handler (echo-reverse svc "Prefix: ")]
          (let [req (assoc catalog-request-nocert :body "Hello World!")
                {:keys [body status]} (echo-handler req)]
            (testing "Request is allowed due to reverse DNS lookup of 127.0.0.1"
              (is (= 401 status))
              (is (= body "Forbidden request: (127.0.0.1) access to /puppet/v3/catalog/localhost (method :get)"))))
          (let [req (assoc catalog-request-nocert :body "Hello World!"
                                                  :uri "/puppet/v3/catalog/s1")
                {:keys [body status]} (echo-handler req)]
            (testing "Request is denied due to unauthenticated request"
              (is (= 401 status))
              (is (= body (str "Forbidden request: (127.0.0.1) "
                               "access to /puppet/v3/catalog/s1 (method :get)"))))))))))
