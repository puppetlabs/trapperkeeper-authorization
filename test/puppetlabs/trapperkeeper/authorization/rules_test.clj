(ns puppetlabs.trapperkeeper.authorization.rules-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.testutils :as testutils :refer [request]]
            [puppetlabs.trapperkeeper.testutils.logging :as logutils]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(defn- request-with-params
  [path params]
  (assoc (request path) :query-params params))

(deftest test-matching-path-rules
  (let [rule (testutils/new-rule :path "/path/to/resource")]
    (testing "matching identical path"
      (is (= (:rule (rules/match? rule (request "/path/to/resource"))) rule)))
    (testing "matching non-identical path"
      (is (nil? (rules/match? rule (request "/path/to/different-resource")))))))

(deftest test-matching-regex-rules
  (let [rule (testutils/new-rule :regex "(resource|path)" :any)]
    (testing "matching path"
      (is (= (:rule (rules/match? rule (request "/going/to/resource"))) rule)))
    (testing "non-matching path"
      (is (nil? (rules/match? rule (request "/other/file")))))))

(deftest test-matching-regex-rules-with-captures
  (let [rule (testutils/new-rule :regex "^/path/(.*?)/(.*?)$" :any)]
    (testing "matching regex returns captures"
      (is (= (:matches (rules/match? rule (request "/path/to/resource"))) [ "to" "resource" ])))))

(deftest test-matching-supports-request-method
  (let [rule (testutils/new-rule :path "/path/to/resource" :delete)]
    (testing "matching identical method"
      (is (= (:rule (rules/match? rule (request "/path/to/resource" :delete))) rule)))
    (testing "non matching method"
      (is (nil? (rules/match? rule (request "/path/to/resource" :get)))))
    (let [path "/path/to/resource"
          methods [:get :put :delete]
          rule (testutils/new-rule :path path methods)]
      (testing "matching rule with multiple methods"
        (doseq [method methods]
          (is (= (:rule (rules/match? rule (request path method))) rule))))
      (doseq [method [:post :head]]
        (testing "no match to rule with multiple methods"
          (is (nil? (rules/match? rule (request path method))))))))
  (let [rule (testutils/new-rule :path "/path/to/resource" :any)]
    (doseq [x [:get :post :put :delete :head]]
      (testing (str "matching " x)
        (is (= (:rule (rules/match? rule (request "/path/to/resource" x))) rule))))))

(deftest test-matching-query-parameters
  (let [rule (testutils/new-rule :path "/path/to/resource" :any)
        foo-rule (rules/query-param rule :environment "foo")
        foo-bar-rule (rules/query-param rule :environment ["foo" "bar"])
        multiples-rule (-> rule
                           (rules/query-param :beatles ["lennon" "starr"])
                           (rules/query-param :monkees "davy"))]

    (testing "request matches rule"
      (are [rule params] (= rule (->> params
                                      (request-with-params "/path/to/resource")
                                      (rules/match? rule)
                                      :rule))
        foo-rule {"environment" "foo"}
        foo-rule {"environment" ["foo" "bar"]}
        foo-bar-rule {"environment" "foo"}
        foo-bar-rule {"environment" "bar"}
        multiples-rule {"beatles" "starr"
                        "monkees" "davy"}))

    (testing "request does not match rule"
      (are [rule params] (->> params
                              (request-with-params "/path/to/resource")
                              (rules/match? rule)
                              nil?)
        foo-rule {"environment" "Foo"}
        foo-rule {"environment" "bar"}
        foo-bar-rule {"environment" "Foo"}
        foo-bar-rule {"environment" "foobar"}
        multiples-rule {"beatles" ["lennon" "starr"]
                        "monkees" "ringo"}))))

(deftest test-rule-acl-creation
  (let [rule (testutils/new-rule :path "/highway/to/hell" :any)]
    (testing "allowing a host"
      (testutils/is-allowed (acl/allowed? (:acl (rules/allow rule "*.domain.com")) "www.domain.com" "127.0.0.1")))
    (testing "several allow in a row"
      (let [new-rule (-> rule (rules/allow "*.domain.com") (rules/allow "*.test.org"))]
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "127.0.0.1"))
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.test.org" "127.0.0.1"))
        (testutils/is-not-allowed (acl/allowed? (:acl new-rule) "www.different.tld" "127.0.0.1"))))
    (testing "allowing an ip"
      (testutils/is-allowed  (acl/allowed? (:acl (rules/allow-ip rule "192.168.1.0/24")) "www.domain.com" "192.168.1.23")))
    (testing "several allow-ip in a row"
      (let [new-rule (-> rule (rules/allow-ip "192.168.1.0/24") (rules/allow-ip "192.168.10.0/24"))]
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "192.168.1.23"))
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "192.168.10.4"))
        (testutils/is-not-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "127.0.0.1")))
    (testing "a mix of allow-ip and allow in a row"
      (let [new-rule (-> rule (rules/allow "*.test.org") (rules/allow-ip "192.168.10.0/24"))]
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.test.org" "192.168.1.23"))
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "192.168.10.4"))
        (testutils/is-not-allowed (acl/allowed? (:acl new-rule) "www.domain.com" "127.0.0.1")))
    (testing "deny-ip"
      (let [new-rule (-> rule (rules/allow "*.test.org") (rules/deny-ip "192.168.10.0/24"))]
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.test.org" "192.168.1.23"))
        (testutils/is-not-allowed (acl/allowed? (:acl new-rule) "www.test.org" "192.168.10.2")))
    (testing "deny"
      (let [new-rule (-> rule (rules/allow-ip "192.168.1.0/24") (rules/deny "*.domain.org"))]
        (testutils/is-allowed (acl/allowed? (:acl new-rule) "www.test.org" "192.168.1.23"))
        (testutils/is-not-allowed (acl/allowed? (:acl new-rule) "www.domain.org" "192.168.10.2")))))))))

(defn- build-rules
  "Build a list of rules from individual vectors of [path allow]"
  [& rules]
  (reduce #(rules/add-rule %1 (-> (testutils/new-rule :path (first %2))
                                  (rules/allow (second %2))))
          rules/empty-rules
          rules))

(deftest test-match-rule
  (let [request (request "/stairway/to/heaven" :get "192.168.1.23")]
    (testing "match-rule"
      ())))

(deftest test-allowed
  (logutils/with-test-logging
    (let [request (-> (request "/stairway/to/heaven" :get "192.168.1.23")
                      (ring/set-authorized-authentic? true))]
      (testing "allowed request by name"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/stairway/to/heaven" "*.domain.org"])]
          (is (rules/authorized? (rules/allowed? rules request "test.domain.org")))))
      (testing "global deny"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/path/to/other" "*.domain.org"])]
          (is (not (rules/authorized? (rules/allowed? rules request "www.domain.org"))))
          (is (= (:message (rules/allowed? rules request "www.domain.org"))
                 "global deny all - no rules matched"))))
      (testing "rule not allowing"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/stairway/to/heaven" "*.domain.org"])]
          (is (not (rules/authorized? (rules/allowed? rules request "www.test.org"))))
          (is (= (:message (rules/allowed? rules request "www.test.org"))
                 (str "Forbidden request: www.test.org(192.168.1.23) access to "
                      "/stairway/to/heaven (method :get) (authentic: true) "
                      "denied by rule 'test rule'.")))))
      (testing "tagged rule not allowing "
        (let [rules (map #(rules/tag-rule %1 "file.txt" 23)
                         (build-rules ["/path/to/resource" "*.domain.org"]
                                      ["/stairway/to/heaven" "*.domain.org"]))]
          (is (not (rules/authorized? (rules/allowed? rules request "www.test.org"))))
          (is (= (:message (rules/allowed? rules request "www.test.org"))
                 (str "Forbidden request: www.test.org(192.168.1.23) access to "
                      "/stairway/to/heaven (method :get) at file.txt:23 "
                      "(authentic: true) denied by rule 'test rule'."))))))))

(deftest test-rule-sorting
  (testing "rules checked in order of sort-order not order of appearance"
    (let [rules (rules/sort-rules
                 [(-> (rules/new-rule :path "/foo" :any 2 "name")
                      (rules/deny "*"))
                  (-> (rules/new-rule :path "/foo" :any 1 "name")
                      (rules/allow "*"))])
          request (-> (request "/foo")
                      (ring/set-authorized-authentic? true))]
      (is (rules/authorized? (rules/allowed? rules request "test.org")))))
  (testing "rules checked in order of name when sort-order is the same"
    (let [rules (rules/sort-rules
                 [(-> (rules/new-rule :path "/foo" :any 1 "bbb")
                      (rules/deny "*"))
                  (-> (rules/new-rule :path "/foo" :any 1 "aaa")
                      (rules/allow "*"))])
          request (-> (request "/foo")
                      (ring/set-authorized-authentic? true))]
      (is (rules/authorized? (rules/allowed? rules request "test.org"))))))

(deftest test-match-report
  (let [request (-> (request "/stairway/to/heaven" :get "192.168.1.23")
                    (ring/set-authorized-authentic? true))
        rules (build-rules ["/path/to/resource" "*.domain.org"] ["/stairway/to/heaven" "*.domain.org"])]
    (testing "embedded request"
      (is (= "/stairway/to/heaven" (get-in (rules/allowed? rules request "test.domain.org") [:match-report :request :path])))
      (is (= "GET" (get-in (rules/allowed? rules request "test.domain.org") [:match-report :request :method])))
      (is (= "test.domain.org" (get-in (rules/allowed? rules request "test.domain.org") [:match-report :request :name])))
      (is (= "192.168.1.23" (get-in (rules/allowed? rules request "test.domain.org") [:match-report :request :ip]))))
    (testing "acl report"
      (is (= 2 (count (get-in (rules/allowed? rules request "test.domain.org") [:match-report :matches]))))
      (is (= [:no :yes] (mapv :match (get-in (rules/allowed? rules request "test.domain.org") [:match-report :matches])))))))

(deftest test-rules-method->string
  (testing "simple method"
    (is "GET" (rules/method->string :get))
    (is "GET,PUT" (rules/method->string [:get :put]))))