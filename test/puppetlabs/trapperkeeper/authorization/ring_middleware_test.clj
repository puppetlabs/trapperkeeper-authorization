(ns puppetlabs.trapperkeeper.authorization.ring-middleware-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as ring-middleware]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.ssl-utils.core :as ssl]
            [schema.test :as schema-test])
  (:import (org.joda.time DateTime Period)))

(use-fixtures :once schema-test/validate-schemas)

(defn- request
  "Builds a ring request"
  [path method certificate ip]
  {:uri path :request-method method :remote-addr ip :ssl-client-cert certificate})

;; Exctracted from ssl-utils test
(defn- generate-not-before-date []
  (-> (DateTime/now)
      (.minus (Period/days 1))
      (.toDate)))

(defn- generate-not-after-date []
  (-> (DateTime/now)
      (.plus (Period/years 5))
      (.toDate)))

(defn- create-certificate
  [cn]
  (let [subject (ssl/cn cn)
        key-pair (ssl/generate-key-pair 512)
        subj-pub (ssl/get-public-key key-pair)
        issuer (ssl/cn "my ca")
        issuer-key-pair (ssl/generate-key-pair 512)
        issuer-priv (ssl/get-private-key issuer-key-pair)
        not-before (generate-not-before-date)
        not-after (generate-not-after-date)
        serial 42]
    (ssl/sign-certificate issuer issuer-priv serial not-before not-after subject subj-pub)))

(def test-domain-cert (create-certificate "test.domain.org"))
(def test-other-cert (create-certificate "www.other.org"))
(def test-denied-cert (create-certificate "bad.guy.com"))

(def test-rule [(-> (rules/new-path-rule "/path/to/foo")
                   (rules/deny "bad.guy.com")
                   (rules/allow-ip "192.168.0.0/24")
                   (rules/allow "*.domain.org")
                   (rules/allow "*.test.com")
                   (rules/deny-ip "192.168.1.0/24"))])

(deftest ring-request-to-name-test
  (testing "request to name"
    (is (= (ring-middleware/request->name (request "/path/to/resource" :get test-domain-cert "127.0.0.1")) "test.domain.org"))))

(def base-handler
  (fn [request]
    {:status 200 :body "hello"}))

(defn build-ring-handler
  [rules]
  (-> base-handler
      (ring-middleware/wrap-authorization-check rules)))

(deftest wrap-authorization-check-test
  (let [ring-handler (build-ring-handler test-rule)]
    (testing "access allowed when cert CN is allowed"
      (let [response (ring-handler (request "/path/to/foo" :get test-domain-cert "127.0.0.1"))]
        (is (= 200 (:status response)))
        (is (= "hello" (:body response)))))
    (testing "access denied when cert CN is not in the rule"
      (let [response (ring-handler (request "/path/to/foo" :get test-other-cert "127.0.0.1"))]
        (is (= 401 (:status response)))
        (is (= "Forbidden request: www.other.org(127.0.0.1) access to /path/to/foo (method :get) (authentic: true)" (:body response)))))
    (testing "access denied when cert CN is explicitely denied in the rule"
      (let [response (ring-handler (request "/path/to/foo" :get test-denied-cert "127.0.0.1"))]
        (is (= 401 (:status response)))
        (is (= "Forbidden request: bad.guy.com(127.0.0.1) access to /path/to/foo (method :get) (authentic: true)" (:body response)))))))

