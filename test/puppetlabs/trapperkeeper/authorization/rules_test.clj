(ns puppetlabs.trapperkeeper.authorization.rules-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.testutils :as testutils]
            [puppetlabs.trapperkeeper.testutils.logging :as logutils]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(defmacro dbg [x] `(let [x# ~x] (println "dbg:" '~x "=" x#) x#))

(defn- request-with-params
  [path params]
  (assoc (testutils/request path) :query-params params))

(deftest test-matching-path-rules
  (let [rule (testutils/new-rule :path "/path/to/resource")]
    (testing "matching identical path"
      (is (= (:rule (rules/match? rule (testutils/request
                                        "/path/to/resource"))) rule)))
    (testing "matching non-identical path"
      (is (nil? (rules/match? rule (testutils/request
                                    "/path/to/different-resource")))))))

(deftest test-matching-regex-rules
  (let [rule (testutils/new-rule :regex "(resource|path)" :any)]
    (testing "matching path"
      (is (= (:rule (rules/match? rule (testutils/request
                                        "/going/to/resource")))
             rule)))
    (testing "non-matching path"
      (is (nil? (rules/match? rule (testutils/request "/other/file")))))))

(deftest test-matching-regex-rules-with-captures
  (let [rule (testutils/new-rule :regex "^/path/(.*?)/(.*?)$" :any)]
    (testing "matching regex returns captures"
      (is (= (:matches (rules/match? rule (testutils/request
                                           "/path/to/resource")))
             [ "to" "resource" ])))))

(deftest test-matching-supports-request-method
  (let [rule (testutils/new-rule :path "/path/to/resource" :delete)]
    (testing "matching identical method"
      (is (= (:rule (rules/match? rule (testutils/request "/path/to/resource"
                                                     :delete))) rule)))
    (testing "non matching method"
      (is (nil? (rules/match? rule
                              (testutils/request "/path/to/resource" :get)))))
    (let [path "/path/to/resource"
          methods [:get :put :delete]
          rule (testutils/new-rule :path path methods)]
      (testing "matching rule with multiple methods"
        (doseq [method methods]
          (is (= (:rule (rules/match? rule (testutils/request path method)))
                 rule))))
      (doseq [method [:post :head]]
        (testing "no match to rule with multiple methods"
          (is (nil? (rules/match? rule (testutils/request path method))))))))
  (let [rule (testutils/new-rule :path "/path/to/resource" :any)]
    (doseq [x [:get :post :put :delete :head]]
      (testing (str "matching " x)
        (is (= (:rule (rules/match? rule
                                    (testutils/request
                                     "/path/to/resource" x)))
               rule))))))

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
      (is (acl/allowed? (:acl (rules/allow rule {:certname "*.domain.com"})) {:certname "www.domain.com" :extensions {}})))
    (testing "several allow in a row"
      (let [new-rule (-> rule (rules/allow {:certname "*.domain.com"}) (rules/allow {:certname "*.test.org"}))]
        (is (acl/allowed? (:acl new-rule) {:certname "www.domain.com" :extensions {}}))
        (is (acl/allowed? (:acl new-rule) {:certname "www.test.org" :extensions {}}))
        (is (not (acl/allowed? (:acl new-rule) {:certname "www.different.tld" :extensions {}})))))
    (testing "deny overrides allow"
      (let [new-rule (-> rule
                         (rules/allow {:certname "*.domain.org"})
                         (rules/deny {:certname "deny.domain.org"}))]
        (is (acl/allowed? (:acl new-rule) {:certname "allow.domain.org" :extensions {}}))
        (is (not (acl/allowed? (:acl new-rule) {:certname "deny.domain.org" :extensions {}})))))))

(defn- build-rules
  "Build a list of rules from individual vectors of [path allow]"
  [& rules]
  (reduce #(conj %1 (-> (testutils/new-rule :path (first %2))
                        (rules/allow {:certname (second %2)})))
          []
          rules))

(deftest test-allowed
  (logutils/with-test-logging
    (let [request (-> (testutils/request
                       "/stairway/to/heaven" :get "192.168.1.23")
                      (ring/set-authorized-authenticated true))]
      (testing "allowed request by name"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/stairway/to/heaven" "*.domain.org"])
              request (ring/set-authorized-name request "test.domain.org")]
          (is (rules/authorized? (rules/allowed? request rules {} nil)))))
      (testing "global deny"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/path/to/other" "*.domain.org"])
              request (ring/set-authorized-name request "www.domain.org")]
          (is (not (rules/authorized? (rules/allowed? request rules {} nil))))
          (is (= (:message (rules/allowed? request rules {} nil))
                 "global deny all - no rules matched"))))
      (testing "rule not allowing"
        (let [rules (build-rules ["/path/to/resource" "*.domain.org"]
                                 ["/stairway/to/heaven" "*.domain.org"])
              request (ring/set-authorized-name request "www.test.org")
              rules-allowed (rules/allowed? request rules {} nil)]
          (is (not (rules/authorized? rules-allowed )))
          (is (= (:message rules-allowed)
                 (str "Forbidden request: /stairway/to/heaven (method :get)."
                      " Please see the server logs for details.")))
          (is (logged?
               (re-pattern (str "Forbidden request: www.test.org\\(192.168.1.23\\)"
                                " access to /stairway/to/heaven \\(method :get\\)"
                                " \\(authenticated: true\\) denied by rule 'test rule'."))
               :error))))
      (testing "tagged rule not allowing "
        (let [rules (map #(rules/tag-rule %1 "file.txt" 23)
                         (build-rules ["/path/to/resource" "*.domain.org"]
                                      ["/stairway/to/heaven" "*.domain.org"]))
              request (ring/set-authorized-name request "www.test.org")
              rules-allowed (rules/allowed? request rules {} nil)]
          (is (not (rules/authorized? rules-allowed)))
          (is (= (:message rules-allowed)
                 (str "Forbidden request: /stairway/to/heaven (method :get)."
                      " Please see the server logs for details.")))
          (is (logged?
               (re-pattern (str "Forbidden request: www.test.org\\(192.168.1.23\\)"
                                " access to /stairway/to/heaven \\(method :get\\)"
                                " at file.txt:23 \\(authenticated: true\\)"
                                " denied by rule 'test rule'.")))))))))

(deftest test-rule-sorting
  (testing "rules checked in order of sort-order not order of appearance"
    (let [rules (rules/sort-rules
                 [(-> (rules/new-rule :path "/foo" :any 2 "name")
                      (rules/deny {:certname "*"}))
                  (-> (rules/new-rule :path "/foo" :any 1 "name")
                      (rules/allow {:certname "*"}))])
          request (-> (testutils/request "/foo")
                      (ring/set-authorized-authenticated true)
                      (ring/set-authorized-name "test.org"))]
      (is (rules/authorized? (rules/allowed? request rules {} nil)))))
  (testing "rules checked in order of name when sort-order is the same"
    (let [rules (rules/sort-rules
                 [(-> (rules/new-rule :path "/foo" :any 1 "bbb")
                      (rules/deny {:certname "*"}))
                  (-> (rules/new-rule :path "/foo" :any 1 "aaa")
                      (rules/allow {:certname "*"}))])
          request (-> (testutils/request "/foo")
                      (ring/set-authorized-authenticated true)
                      (ring/set-authorized-name "test.org"))]
      (is (rules/authorized? (rules/allowed? request rules {} nil))))))
