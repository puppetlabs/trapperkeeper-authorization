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
  echo-reverse-service EchoReverseService [[:AuthorizationService wrap-handler]]
  (echo-reverse
    [this msg]
    (let [handler (fn [req] (response (str msg (str/reverse (:body req)))))]
      (wrap-handler handler))))

(def minimal-config
  "Minimal config required to bootstrap AuthorizationService with
  EchoReverseService as a dependant consumer.

  An empty list representing no rules with an expected behavior of
  default-deny originating in the authorization library itself."
  {:authorization {:rules []}})

(def base-request
  "A basic request to feed into the tests"
  {:uri "/foo/bar"
   :request-method :get
   :remote-addr "127.0.0.1"})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest ^:integration wrap-handler-test
  (with-test-logging
    (with-app-with-config
      app
      [echo-reverse-service authorization-service]
      minimal-config
      (testing "The echo-reverse service function"
        (let [svc (get-service app :EchoReverseService)
              echo-handler (echo-reverse svc "Prefix: ")
              req (assoc base-request :body "Hello World!")
              {:keys [body status]} (echo-handler req)]
          (is (= 401 status))
          (is (= "global deny all - no rules matched" body)))))))
