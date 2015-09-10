(ns puppetlabs.trapperkeeper.authorization.ring-middleware-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as ring-middleware]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.testutils :refer :all]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(def test-rule [(-> (rules/new-rule :path "/path/to/foo")
                    (rules/deny "bad.guy.com")
                    (rules/allow-ip "192.168.0.0/24")
                    (rules/allow "*.domain.org")
                    (rules/allow "*.test.com")
                    (rules/deny-ip "192.168.1.0/24"))])

(deftest ring-request-to-name-test
  (testing "request to name"
    (is (= (ring-middleware/request->name (request "/path/to/resource" :get "127.0.0.1" test-domain-cert)) "test.domain.org"))))

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
      (let [response (ring-handler (request "/path/to/foo" :get "127.0.0.1" test-domain-cert))]
        (is (= 200 (:status response)))
        (is (= "hello" (:body response)))))
    (testing "access denied when cert CN is not in the rule"
      (let [response (ring-handler (request "/path/to/foo" :get "127.0.0.1" test-other-cert))]
        (is (= 403 (:status response)))
        (is (= "Forbidden request: www.other.org(127.0.0.1) access to /path/to/foo (method :get) (authentic: true)" (:body response)))))
    (testing "access denied when cert CN is explicitly denied in the rule"
      (let [response (ring-handler (request "/path/to/foo" :get "127.0.0.1" test-denied-cert))]
        (is (= 403 (:status response)))
        (is (= "Forbidden request: bad.guy.com(127.0.0.1) access to /path/to/foo (method :get) (authentic: true)" (:body response))))))
  (testing "Denied when deny all"
    (let [app (build-ring-handler [(-> (rules/new-rule :path "/")
                                       (rules/deny "*"))])]
      (doseq [path ["a" "/" "/hip/hop/" "/a/hippie/to/the/hippi-dee/beat"]]
        (let [req (request path :get "127.0.0.1" test-domain-cert)
              {status :status} (app req)]
          (is (= status 403)))))))
