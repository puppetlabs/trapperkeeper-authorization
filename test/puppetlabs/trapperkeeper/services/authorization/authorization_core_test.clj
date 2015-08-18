(ns puppetlabs.trapperkeeper.services.authorization.authorization-core-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.services.authorization.authorization-core :refer :all]
            [schema.test]))

(use-fixtures :once schema.test/validate-schemas)

(def base-path-auth {:path "/foo/bar/baz", :type "path"})
(def base-regex-auth {:path "(incoming|outgoing)", :type "regex"})
(def allow-single {:allow "www.domain.org"})
(def allow-list {:allow ["*.domain.org" "*.test.com"]})
(def deny-single {:deny "bald.guy.com"})
(def deny-list {:deny ["bald.eagle.com" "bald.bull.com"]})

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
            deny [deny-list deny-single nil]]
      (let [rule (merge base allow deny)]
        (when (or allow deny)
          (is (= rule (validate-auth-config-rule! rule))))))))

(deftest invalid-configs-fail
  (testing "Missing keys are not valid"
    (is (thrown-with-msg? IllegalArgumentException
          #"An authorization rule should be specified as a map"
          (validate-auth-config-rule! 0)))

    (is (thrown-with-msg? IllegalArgumentException
          #".* does not contain a 'path' key."
          (validate-auth-config-rule! {:type "path"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* does not contain a 'type' key."
          (validate-auth-config-rule! {:path "/path"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* must contain either a 'deny' or 'allow' rule."
          (validate-auth-config-rule! {:path "/foo/bar/baz"
                                       :type "path"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be set to either 'path' or 'regex'."
          (validate-auth-config-rule! {:path "/who/cares"
                                       :type "not-a-type"
                                       :allow "hillbillies"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* It should be a string."
          (validate-auth-config-rule! {:path 42
                                       :type "path"
                                       :allow "hicks"})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* is not a string."
          (validate-auth-config-rule! {:path "/"
                                       :type "path"
                                       :allow 23})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* contains one or more names that are not strings."
          (validate-auth-config-rule! {:path "/"
                                       :type "path"
                                       :deny ["one.anem" 23]})))

    (is (thrown-with-msg? IllegalArgumentException
          #".* Dangling meta character '\*' near index 0[.\s]*"
          (validate-auth-config-rule! {:path  "*."
                                       :type  "regex"
                                       :allow "somewhere"})))))

(deftest transform-config-test
  (testing "Basic rules are translated properly"
    (let [{:keys [type path method]}
          (transform-config-rule (merge base-path-auth allow-list))]
      (is (= :string type))
      (is (= (str path) (str #"/foo/bar/baz")))
      (is (= :any method)))

    (let [{:keys [type path method]}
          (transform-config-rule (merge base-regex-auth allow-single))]
      (is (= :regex type))
      (is (= (str path) "(incoming|outgoing)"))
      (is (= :any method)))))

(deftest transform-config-rule-to-acl-test
  (testing "Empty config rule map returns an empty ACL sorted set"
    (is (= #{} (transform-config-rule-to-acl {}))))
  (testing "Multiple allow and deny statements in a single path rule"
    (let [config-rule (merge base-path-auth allow-single deny-single)
          acl (transform-config-rule-to-acl config-rule)]
      (is (= expected-acl-as-vec (vec acl)))))
  (testing "Deny rules come before allow rules in the resulting ACL"
    (let [config-rule (merge base-path-auth deny-list allow-list)
          acl (transform-config-rule-to-acl config-rule)]
      (is (= :deny (:auth-type (first acl))))
      (is (= :deny (:auth-type (second acl))))
      (is (= [:deny :deny :allow :allow] (vec (map :auth-type acl))))))
  (testing "Allow rules with no deny are returned in order"
    (let [config-rule (merge base-path-auth allow-list)
          acl (transform-config-rule-to-acl config-rule)]
      (is (= ["com" "test"] (:pattern (first acl))))
      (is (= :inexact (:qualifier (first acl))))
      (is (= ["org" "domain"] (:pattern (second acl))))
      (is (= :inexact (:qualifier (second acl))))))
  (testing "Deny rules with no allow are returned in order"
    (let [config-rule (merge base-path-auth deny-list)
          acl (transform-config-rule-to-acl config-rule)]
      (is (= ["com" "bull" "bald"] (:pattern (first acl))))
      (is (= :exact (:qualifier (first acl))))
      (is (= ["com" "eagle" "bald"] (:pattern (second acl))))
      (is (= :exact (:qualifier (first acl)))))))




