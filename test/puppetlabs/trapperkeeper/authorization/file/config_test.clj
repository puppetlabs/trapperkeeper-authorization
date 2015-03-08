(ns puppetlabs.trapperkeeper.authorization.file.config-test
  (:import (com.typesafe.config ConfigFactory))
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.file.config :as config]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(def test-resources-dir "./dev-resources/puppetlabs/trapperkeeper/authorization/file/config")

(def ConfigRuleFixture (ConfigFactory/parseString "
{
  path: /path/to/resource
  type: path
  allow: [ \"*.domain.org\", \"*.test.com\" ]
  allow-ip: \"192.168.0.0/24\"
  deny: \"bad.guy.com\"
  deny-ip: \"192.168.1.0/24\"
}
"))

(def ExpectedRule (-> (rules/new-path-rule "/path/to/resource")
                      (rules/deny "bad.guy.com")
                      (rules/allow-ip "192.168.0.0/24")
                      (rules/allow "*.domain.org")
                      (rules/allow "*.test.com")
                      (rules/deny-ip "192.168.1.0/24")))

(def ConfigRulesFixture (ConfigFactory/parseString "
rules = [
  {
    path: /path/to/resource
    type: path
    allow: [ \"*.domain.org\", \"*.test.com\" ]
    allow-ip: \"192.168.0.0/24\"
    deny: \"bad.guy.com\"
    deny-ip: \"192.168.1.0/24\"
  },
  {
    type: regex
    path: \"(incoming|outgoing)\"
    allow: \"www.domain.org\"
  }
  ]
"))

(def ExpectedRules (-> (rules/add-rule rules/empty-rules ExpectedRule)
                       (rules/add-rule (-> (rules/new-regex-rule "(incoming|outgoing)")
                                           (rules/allow "www.domain.org")))))


(deftest config->rule-test
  (testing "produce a rule with the correct path, type and acl"
    (is (rules/equals-rule (config/config->rule ConfigRuleFixture) ExpectedRule))))

(deftest config->rules-test
  (testing "produce a vector of rules with the correct path, type and acl"
    (is (rules/equals-rules (config/config->rules ConfigRulesFixture) ExpectedRules))))

(deftest config-file->rules-test
  (let [fixture (str test-resources-dir "/fixture1.conf")]
    (testing "produce a vector of rules with the correct path, type and acl from a file"
      (is (rules/equals-rules (config/config-file->rules fixture) ExpectedRules)))
    (testing "produce rules with file tags"
      (is (= (:file (first (config/config-file->rules fixture))) fixture))
      (is (= (:file (second (config/config-file->rules fixture))) fixture)))
    (testing "produce rules with line tags"
      (is (= (:line (first (config/config-file->rules fixture))) 2))
      (is (= (:line (second (config/config-file->rules fixture))) 10)))))

