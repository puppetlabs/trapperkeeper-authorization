(ns puppetlabs.trapperkeeper.services.authorization.authorization-core-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [schema.test]
            [puppetlabs.kitchensink.core :refer [dissoc-in]]))

(use-fixtures :once schema.test/validate-schemas)

(def minimal-rule {:match-request {:path ""} :sort-order 500 :name "minimal"})
(def base-path-auth {:match-request {:path "/foo/bar/baz" :type "path"}
                     :sort-order 500 :name "base-path-auth"})
(def base-regex-auth {:match-request {:path "(incoming|outgoing)" :type "regex"}
                      :sort-order 500 :name "base-regex-auth"})
(def allow-single {:allow "www.domain.org"})
(def allow-list {:allow ["*.domain.org" "*.test.com"]})
(def deny-single {:deny "bald.guy.com"})
(def deny-list {:deny ["bald.eagle.com" "bald.bull.com"]})
(def single-query-param {:match-request {:query-params {:environment "production"}}})
(def multi-query-param {:match-request {:query-params {:env ["prod" "staging"]}}})
(def allow-unauthenticated {:allow-unauthenticated true})
(def method-get {:match-request {:method "get"}})
(def method-put {:match-request {:method "put"}})
(def multiple-methods {:match-request {:method ["get" "put"]}})

(def expected-acl-as-vec
  "The expected ACL given the configuration of a base-path combined with
   allow-single and deny-single.  The API returns a sorted-set and so
   this is a vector to allow easy ordered comparison in the tests.
   Pass the ACL through the vec function when asserting against this
   definition."
  [{:auth-type :deny
    :value   ["com"
                "guy"
                "bald"]
    :match      :string}
   {:auth-type :allow
    :value   ["org"
                "domain"
                "www"]
    :match      :string}])

(deftest valid-configs-pass
  (testing "Valid forms of a auth config pass"
    (doseq [base [base-path-auth base-regex-auth]
            allow [allow-list allow-single nil]
            deny [deny-list deny-single nil]
            methods [{} method-get method-put multiple-methods]
            params [single-query-param multi-query-param]]
      (let [rule (merge-with merge base allow deny params methods)]
        (when (or allow deny)
          (is (= rule (validate-auth-config-rule! rule))))
        (let [parsed (config->rule rule)]
          (is (= (:sort-order parsed) (:sort-order rule)))
          (is (= (:name parsed) (:name rule)))
          (is (false? (contains? parsed :match-request))))))))

(def testrule
  "A valid rule definition as it would be found in the configuration file."
  {:name "name"
   :sort-order 1
   :allow "allow"
   :match-request {:path "/path" :type "path"}})

(deftest invalid-configs-fail
  (testing "Configuration section required"
    (is (thrown-with-msg?
         IllegalArgumentException
         #"Missing authorization service configuration."
         (validate-auth-config! nil))))

  (testing "Version number required in configuration"
    (doseq [invalid [{:rules []}
                     {:rules [] :version 0}
                     {:rules [] :version "1"}]]
      (is (thrown-with-msg?
           IllegalArgumentException
           #"Unsupported or missing version in configuration file.*"
           (validate-auth-config! invalid)))))

  (testing "allow-header-cert-info is a boolean"
    (is (thrown-with-msg?
         IllegalArgumentException
         #"allow-header-cert-info is not a boolean"
         (validate-auth-config! {:version 1
                                 :rules []
                                 :allow-header-cert-info "maybe?"}))))

  (testing "Rule names must be unique"
    (is (thrown-with-msg?
         IllegalArgumentException
         #".* Rules must be uniquely named."
         (validate-auth-config! {:version 1
                                 :rules [testrule testrule]}))))

  (testing "With allow-unauthenticated true and allow rules"
    (let [rule (merge base-path-auth allow-unauthenticated allow-single)]
      (is (thrown-with-msg?
           IllegalArgumentException
           #"cannot have allow or deny if allow-unauthenticated"
           (validate-auth-config-rule! rule)))))

  (testing "Missing keys are not valid"
    (is (thrown-with-msg?
          IllegalArgumentException
          #"An authorization rule should be specified as a map."
          (validate-auth-config-rule! 0)))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"An authorization rule must contain a 'match-request' section."
          (validate-auth-config-rule! (dissoc testrule :match-request))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* does not contain a 'path' key."
          (validate-auth-config-rule!
            (dissoc-in testrule [:match-request :path]))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* does not contain a 'type' key."
          (validate-auth-config-rule!
            (dissoc-in testrule [:match-request :type]))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* does not contain a 'sort-order' key."
          (validate-auth-config-rule! (dissoc testrule :sort-order))))

    (doseq [invalid ["notanumber" 0 1000]]
      (is (thrown-with-msg?
            IllegalArgumentException
            #".* It should be a number from 1 to 999."
            (validate-auth-config-rule! (assoc testrule :sort-order invalid)))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* does not contain a 'name' key."
          (validate-auth-config-rule! (dissoc testrule :name))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* must contain either a 'deny' or 'allow' rule."
          (validate-auth-config-rule! (dissoc testrule :allow))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* It should be set to either 'path' or 'regex'."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :type] "not-a-type"))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :path] 42))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule! (assoc testrule :allow 23))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* contains one or more aces that are not maps or strings."
          (validate-auth-config-rule! (assoc testrule :deny ["one.anem" 23]))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* Dangling meta character '\*' near index 0[.\s]*"
          (validate-auth-config-rule!
            (-> testrule
                (assoc-in [:match-request :type] "regex")
                (assoc-in [:match-request :path] "*.")))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"Rule query-params must be a map."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :query-params] []))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :query-params]
                      {0 []}))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* It should be a string or list of strings."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :query-params]
                      {:env :notastringorlist}))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* contains one or more values that are not strings."
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :query-params]
                      {:env [:notastring]}))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* 'delete', 'get', 'head', 'post', 'put'"
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :method] "gross"))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #".* 'delete', 'get', 'head', 'post', 'put'"
          (validate-auth-config-rule!
            (assoc-in testrule [:match-request :method] ["nasty" "gross"]))))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"contains the back reference '\$1' which refers to a capture group in the regex that doesn't exist."
          (validate-auth-config-rule!
            {:match-request {:path "/some/thing" :type "regex"}
             :allow "$1"
             :sort-order 500
             :name "base-regex-auth"})))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"contains the back reference '\$2' which refers to a capture group in the regex that doesn't exist."
          (validate-auth-config-rule!
            {:match-request {:path "/some/(thing)" :type "regex"}
             :allow "$1$2"
             :sort-order 500
             :name "base-regex-auth"})))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"contains the back reference '\$1' which refers to a capture group in the regex that doesn't exist."
          (validate-auth-config-rule!
            {:match-request {:path "/some/thing" :type "regex"}
             :deny "$1"
             :sort-order 500
             :name "base-regex-auth"})))

    (is (thrown-with-msg?
          IllegalArgumentException
          #"contains the back reference '\$2' which refers to a capture group in the regex that doesn't exist."
          (validate-auth-config-rule!
            {:match-request {:path "/some/(thing)" :type "regex"}
             :deny "$1$2"
             :sort-order 500
             :name "base-regex-auth"})))
    ))

(deftest config->rule-test
  (testing "Given a basic allow rule against a string path"
    (let [m (merge base-path-auth allow-list)
          {:keys [type path method]} (config->rule m)]
      (is (= :path type))
      (testing "path is converted to an quoted regular expression"
        (is (= (str path) "^\\Q/foo/bar/baz\\E")))
      (is (= :any method))))
  (testing "Given a basic allow rule with a specific :put method"
    (let [m (merge-with merge base-path-auth allow-list
                        {:match-request {:method "put"}})
          {:keys [type path method]} (config->rule m)]
      (is (= :path type))
      (testing "path is converted to an quoted regular expression"
        (is (= (str path) "^\\Q/foo/bar/baz\\E")))
      (is (= :put method))))
  (testing "Given a rule config with query parameters"
    (is (= {:env #{"prod" "staging"}}
           (-> (merge-with merge multi-query-param base-path-auth)
               config->rule
               :query-params)))
    (testing "single values are converted to sets"
      (is (= {:environment #{"production"}}
             (-> (merge-with merge single-query-param base-path-auth)
                 config->rule
                 :query-params)))))
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
        (is (= ["org" "domain"] (:value (first acl))))
        (is (= ["com" "test"] (:value (second acl))))))
    (testing "Deny rules with no allow are returned in order"
      (let [m (merge base-path-auth deny-list)
            {:keys [acl]} (config->rule m)]
        (is (= ["com" "eagle" "bald"] (:value (first acl))))
        (is (= ["com" "bull" "bald"] (:value (second acl))))))))
