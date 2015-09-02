(ns puppetlabs.trapperkeeper.services.authorization.authorization-core-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [schema.test]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]))

(use-fixtures :once schema.test/validate-schemas)

(def minimal-rule {:match-request {:path ""}})
(def base-path-auth {:match-request {:path "/foo/bar/baz" :type "path"}})
(def base-regex-auth {:match-request {:path "(incoming|outgoing)" :type "regex"}})
(def allow-single {:allow "www.domain.org"})
(def allow-list {:allow ["*.domain.org" "*.test.com"]})
(def deny-single {:deny "bald.guy.com"})
(def deny-list {:deny ["bald.eagle.com" "bald.bull.com"]})
(def single-query-param {:match-request
                         {:query-params {"environment" "production"}}})
(def multi-query-param {:match-request
                        {:query-params {"env" ["prod" "staging"]}}})
(def allow-unauthenticated {:allow_unauthenticated true})

(def expected-acl-as-vec
  "The expected ACL given the configuration of a base-path combined with
   allow-single and deny-single.  The API returns a sorted-set and so
   this is a vector to allow easy ordered comparison in the tests.
   Pass the ACL through the vec function when asserting against this
   definition."
  [{:auth-type :deny
    :length    nil
    :pattern   ["com"
                "guy"
                "bald"]
    :qualifier :exact
    :type      :domain}
   {:auth-type :allow
    :length    nil
    :pattern   ["org"
                "domain"
                "www"]
    :qualifier :exact
    :type      :domain}])

(deftest valid-configs-pass
  (testing "Valid forms of a auth config pass"
    (doseq [base [base-path-auth base-regex-auth]
            allow [allow-list allow-single nil]
            deny [deny-list deny-single nil]
            params [single-query-param multi-query-param]]
      (let [rule (merge-with merge base allow deny params)]
        (when (or allow deny)
          (is (= rule (validate-auth-config-rule! rule))))))))

(deftest invalid-configs-fail
  (testing "With allow_unauthenticated true and allow rules"
    (let [rule (merge base-path-auth allow-unauthenticated allow-single)]
      (is (thrown-with-msg? IllegalArgumentException
            #"cannot have allow or deny if allow_unauthenticated"
            (validate-auth-config-rule! rule)))))
  (testing "Missing keys are not valid"
    (is (thrown-with-msg? IllegalArgumentException
          #"An authorization rule should be specified as a map."
          (validate-auth-config-rule! 0)))

    (is (thrown-with-msg? IllegalArgumentException
          #"An authorization rule must contain a 'match-request' section."
          (validate-auth-config-rule! {:type "path"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* does not contain a 'path' key."
          (validate-auth-config-rule! {:match-request {:type "path"}})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* does not contain a 'type' key."
          (validate-auth-config-rule! {:match-request {:path "/path"}})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* must contain either a 'deny' or 'allow' rule."
          (validate-auth-config-rule! {:match-request
                                       {:path "/foo/bar/baz"
                                        :type "path"}})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be set to either 'path' or 'regex'."
          (validate-auth-config-rule! {:match-request
                                       {:path "/who/cares"
                                        :type "not-a-type"}
                                       :allow "hillbillies"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule! {:match-request
                                       {:path 42
                                        :type "path"}
                                       :allow "hicks"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"}
                                       :allow 23})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* contains one or more names that are not strings."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"}
                                       :deny ["one.anem" 23]})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* Dangling meta character '\*' near index 0[.\s]*"
          (validate-auth-config-rule! {:match-request
                                       {:path  "*."
                                        :type  "regex"}
                                       :allow "somewhere"})))

    (is (thrown-with-msg? IllegalArgumentException
          #"Rule query-params must be a map."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"
                                        :query-params []}
                                       :allow "*"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"
                                        :query-params {:notastring []}}
                                       :allow "*"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be a string or list of strings."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"
                                        :query-params {"env" :notastringorlist}}
                                       :allow "*"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* contains one or more values that are not strings."
          (validate-auth-config-rule! {:match-request
                                       {:path "/"
                                        :type "path"
                                        :query-params {"env" [:notastring]}}
                                       :allow "*"})))))

(deftest config->rule-test
  (testing "Given a basic allow rule against a string path"
    (let [m (merge base-path-auth allow-list)
          {:keys [type path method]} (config->rule m)]
      (is (= :string type))
      (testing "path is converted to an quoted regular expression"
        (is (= (str path) "^\\Q/foo/bar/baz\\E")))
      (is (= :any method))))
  (testing "Given a basic allow rule with a specific :put method"
    (let [m (merge-with merge base-path-auth allow-list
                        {:match-request {:method :put}})
          {:keys [type path method]} (config->rule m)]
      (is (= :string type))
      (testing "path is converted to an quoted regular expression"
        (is (= (str path) "^\\Q/foo/bar/baz\\E")))
      (is (= :put method))))
  (testing "The ACL of the rule"
    (testing "When the configuration has no allow or deny entries"
      (let [{:keys [acl]} (config->rule minimal-rule)]
        (is (empty? acl) "is empty")))
    (testing "When the configuration has multiple allow and deny statements"
      (let [m (merge base-path-auth allow-single deny-single)
            {:keys [acl]} (config->rule m)]
        (is (= expected-acl-as-vec (vec acl)) "matches exactly")))
    (testing "Deny rules come before allow rules in the resulting ACL"
      (let [m (merge base-path-auth deny-list allow-list)
            {:keys [acl]} (config->rule m)]
        (is (= :deny (:auth-type (first acl))) "first entry is deny")
        (is (= :deny (:auth-type (second acl))) "second entry is deny")
        (is (= [:deny :deny :allow :allow] (vec (map :auth-type acl)))
            "allow entries follow deny entries")))
    (testing "Allow rules with no deny are returned in order"
      (let [m (merge base-path-auth allow-list)
            {:keys [acl]} (config->rule m)]
        (is (= ["com" "test"] (:pattern (first acl))))
        (is (= :inexact (:qualifier (first acl))))
        (is (= ["org" "domain"] (:pattern (second acl))))
        (is (= :inexact (:qualifier (second acl))))))
    (testing "Deny rules with no allow are returned in order"
      (let [m (merge base-path-auth deny-list)
            {:keys [acl]} (config->rule m)]
        (is (= ["com" "bull" "bald"] (:pattern (first acl))))
        (is (= :exact (:qualifier (first acl))))
        (is (= ["com" "eagle" "bald"] (:pattern (second acl))))
        (is (= :exact (:qualifier (first acl))))))
    (testing "Given a rule config with query parameters"
      (is (= {"env" #{"prod" "staging"}}
             (-> (merge-with merge multi-query-param base-path-auth)
                 config->rule
                 :query-params)))
      (testing "single values are converted to sets"
        (is (= {"environment" #{"production"}}
               (-> (merge-with merge single-query-param base-path-auth)
                   config->rule
                   :query-params)))))))
